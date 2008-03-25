/*
 * Copyright (C) 2008 AG Projects
 * Author: Ruud Klaver <ruud@ag-projects.com>
 *
 * Implements low level connection tracking manipulation for MediaProxy.
 *
 */

#include <Python.h>
#include <structmember.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libiptc/libiptc.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define DEFAULT_TIMEOUT 60

static PyObject *ConntrackError;

#define IPTC_ENTRY_SIZE IPT_ALIGN(sizeof(struct ipt_entry))
#define IPTC_MATCH_SIZE IPT_ALIGN(sizeof(struct ipt_entry_match) + sizeof(struct ipt_udp))
#define IPTC_TARGET_SIZE IPT_ALIGN(sizeof(struct ipt_entry_target))
#define IPTC_FULL_SIZE IPTC_ENTRY_SIZE + IPTC_MATCH_SIZE + IPTC_TARGET_SIZE

enum {
    CALLER_REMOTE = 0,
    CALLEE_REMOTE,
    CALLER_LOCAL,
    CALLEE_LOCAL
};

enum {
    COUNTER_CALLER_PACKET_COUNT = 0,
    COUNTER_CALLER_BYTE_COUNT,
    COUNTER_CALLEE_PACKET_COUNT,
    COUNTER_CALLEE_BYTE_COUNT
};


typedef struct RelayStream {
    PyObject_HEAD
    
    struct nf_conntrack *conntrack;
    int is_active;
    int done_init;
    struct RelayStream *prev;
    struct RelayStream *next;
    uint32_t counter[4];
    PyObject *dict;
} RelayStream;

typedef struct ExpireWatcher {
    PyObject_HEAD

    struct nfct_handle *ct_handle;
} ExpireWatcher;

typedef struct ConntrackBlock {
    PyObject_HEAD

    int done_init;
    struct ipt_entry *entry;
} ConntrackBlock;


static RelayStream *RelayStream_head = NULL;


static int
conntrack_cb_one(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    struct nf_conntrack **found_conntrack = (struct nf_conntrack **) data;

    *found_conntrack = nfct_clone(ct);
    return NFCT_CB_STOP;
}


static int
RelayStream_traverse(RelayStream *self, visitproc visit, void *arg)
{
    Py_VISIT(self->dict);
    return 0;
}


static int
RelayStream_clear(RelayStream *self)
{
    Py_CLEAR(self->dict);
    return 0;
}


static PyObject *
RelayStream_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    RelayStream *self;
    int i;

    self = (RelayStream *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->is_active = 0;
        self->done_init = 0;
        self->prev = NULL;
        self->next = NULL;
        if ((self->dict = PyDict_New()) == NULL) {
            Py_DECREF(self);
            return NULL;
        }
        for (i = 0; i < 4; i++)
            self->counter[i] = 0;
        if ((self->conntrack = nfct_new()) == NULL) {
            Py_DECREF(self->dict);
            Py_DECREF(self);
            PyErr_NoMemory();
            return NULL;
        }
        nfct_set_attr_u8(self->conntrack, ATTR_ORIG_L3PROTO, AF_INET);
        nfct_set_attr_u8(self->conntrack, ATTR_ORIG_L4PROTO, IPPROTO_UDP);
    }
            
    return (PyObject *) self;
}


static void
RelayStream_dealloc(RelayStream *self)
{
    struct nfct_handle *ct_handle;

    if (self->is_active)
    {
        if (self->prev == NULL)
            RelayStream_head = self->next;
        else
            self->prev->next = self->prev->next;
        if (self->next != NULL)
            self->next->prev = self->prev;

        Py_BEGIN_ALLOW_THREADS
        ct_handle = nfct_open(CONNTRACK, 0);
        if (ct_handle != NULL) {
            nfct_query(ct_handle, NFCT_Q_DESTROY, self->conntrack);
            nfct_close(ct_handle);
        }
        Py_END_ALLOW_THREADS
    }

    RelayStream_clear(self);
    nfct_destroy(self->conntrack);
    self->ob_type->tp_free((PyObject *) self);
}


static int
RelayStream_init(RelayStream *self, PyObject *args, PyObject *kwds)
{
    char *address_string[4];
    struct in_addr address[4];
    int port[4], i, result;
    unsigned int timeout = DEFAULT_TIMEOUT, mark = 0;
    struct nfct_handle *ct_handle;

    if (self->done_init)
        return 0;

    if (kwds && PyDict_Size(kwds) > 0) {
        PyErr_SetString(PyExc_TypeError, "Keyword arguments not supported");
        return -1;
    }

    if (!PyArg_ParseTuple(args, "(si)(si)(si)(si)|II",
                         &address_string[CALLER_REMOTE], &port[CALLER_REMOTE],
                         &address_string[CALLEE_REMOTE], &port[CALLEE_REMOTE],
                         &address_string[CALLER_LOCAL], &port[CALLER_LOCAL],
                         &address_string[CALLEE_LOCAL], &port[CALLEE_LOCAL],
                         &mark, &timeout))
        return -1;

    for (i = 0; i < 4; i++) {
        if (!inet_aton(address_string[i], &address[i])) {
            PyErr_Format(PyExc_ValueError, "Invalid IP address given: \"%s\"", address_string[i]);
            return -1;
        }
        if (port[i] < 0 || port[i] > 65535) {
            PyErr_SetString(PyExc_ValueError, "UDP port should be between 0 and 65535");
            return -1;
        }
    }

    Py_BEGIN_ALLOW_THREADS
    ct_handle = nfct_open(CONNTRACK, 0);
    Py_END_ALLOW_THREADS
    if (ct_handle == NULL) {
        PyErr_SetString(ConntrackError, strerror(errno));
        return -1;
    }

    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_SRC, address[CALLER_REMOTE].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_SRC, htons(port[CALLER_REMOTE]));
    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_DST, address[CALLER_LOCAL].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_DST, htons(port[CALLER_LOCAL]));
    nfct_query(ct_handle, NFCT_Q_DESTROY, self->conntrack);

    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_SRC, address[CALLEE_REMOTE].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_SRC, htons(port[CALLEE_REMOTE]));
    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_DST, address[CALLEE_LOCAL].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_DST, htons(port[CALLEE_LOCAL]));
    nfct_query(ct_handle, NFCT_Q_DESTROY, self->conntrack);

    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_SRC, address[CALLER_REMOTE].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_SRC, htons(port[CALLER_REMOTE]));
    nfct_set_attr_u32(self->conntrack, ATTR_ORIG_IPV4_DST, address[CALLER_LOCAL].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_ORIG_PORT_DST, htons(port[CALLER_LOCAL]));
    nfct_setobjopt(self->conntrack, NFCT_SOPT_SETUP_REPLY);
    nfct_set_attr_u32(self->conntrack, ATTR_DNAT_IPV4, address[CALLEE_REMOTE].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_DNAT_PORT, htons(port[CALLEE_REMOTE]));
    nfct_set_attr_u32(self->conntrack, ATTR_SNAT_IPV4, address[CALLEE_LOCAL].s_addr);
    nfct_set_attr_u16(self->conntrack, ATTR_SNAT_PORT, htons(port[CALLEE_LOCAL]));
    nfct_set_attr_u32(self->conntrack, ATTR_TIMEOUT, timeout);
    nfct_set_attr_u32(self->conntrack, ATTR_MARK, mark);
    Py_BEGIN_ALLOW_THREADS
    result = nfct_query(ct_handle, NFCT_Q_CREATE, self->conntrack);
    Py_END_ALLOW_THREADS
    if (result) {
        nfct_close(ct_handle);
        PyErr_SetString(ConntrackError, strerror(errno));
        return -1;
    }

    Py_BEGIN_ALLOW_THREADS
    nfct_close(ct_handle);
    Py_END_ALLOW_THREADS
    if (RelayStream_head != NULL) {
        self->next = RelayStream_head;
        RelayStream_head->prev = self;
    }
    RelayStream_head = self;
    self->is_active = 1;
    self->done_init = 1;
    return 0;
}


struct nf_conntrack *
RelayStream_retrieve_ct(RelayStream *self)
{
    struct nfct_handle *ct_handle;
    struct nf_conntrack *conntrack = NULL;

    if ((ct_handle = nfct_open(CONNTRACK, 0)) == NULL) {
        PyErr_SetString(ConntrackError, strerror(errno));
        return NULL;
    }

    if (nfct_callback_register(ct_handle, NFCT_T_ALL, conntrack_cb_one, &conntrack)) {
        nfct_close(ct_handle);
        PyErr_SetString(ConntrackError, strerror(errno));
        return NULL;
    }

    if (nfct_query(ct_handle, NFCT_Q_GET, self->conntrack) || (conntrack == NULL)) {
        nfct_close(ct_handle);
        if (errno == ENOENT)
            PyErr_SetString(ConntrackError, "Connection tracking entry is already removed");
        else
            PyErr_SetString(ConntrackError, strerror(errno));
        return NULL;
    }

    nfct_close(ct_handle);
    return conntrack;
}


typedef struct {
    enum nf_conntrack_attr type;
    int counter_index;
} RelayStream_get_attr_type;


static PyObject *
RelayStream_get_attr(RelayStream *self, void *closure)
{
    struct nf_conntrack *conntrack;
    uint32_t attr;
    RelayStream_get_attr_type *type;

    type = (RelayStream_get_attr_type *) closure;
    if (self->is_active) {
        if ((conntrack = RelayStream_retrieve_ct(self)) == NULL)
            return NULL;
        attr = nfct_get_attr_u32(conntrack, type->type);
        nfct_destroy(conntrack);
        return Py_BuildValue("I", attr);
    } else 
        if (type->counter_index >= 0)
            attr = self->counter[type->counter_index];
        else
            attr = 0;

    return Py_BuildValue("I", attr);
}


static int
RelayStream_set_timeout(RelayStream *self, PyObject *value, void *closure)
{
    struct nf_conntrack *conntrack;
    struct nfct_handle *ct_handle;
    unsigned long timeout;

    if (value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete the timeout attribute");
        return -1;
    }
  
    if (!PyInt_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "The timeout attribute value must be an int");
        return -1;
    }

    timeout = PyInt_AsUnsignedLongMask(value);
    if (timeout > UINT32_MAX) {
        PyErr_SetString(PyExc_ValueError, "Timeout value too large");
        return -1;
    }

    if ((ct_handle = nfct_open(CONNTRACK, 0)) == NULL) {
        PyErr_SetString(ConntrackError, strerror(errno));
        return -1;
    }

    if ((conntrack = RelayStream_retrieve_ct(self)) == NULL) {
        nfct_close(ct_handle);
        return -1;
    } else {
        nfct_set_attr_u32(conntrack, ATTR_TIMEOUT, timeout);

        if (nfct_query(ct_handle, NFCT_Q_UPDATE, conntrack)) {
            nfct_destroy(conntrack);
            nfct_close(ct_handle);
            PyErr_SetString(ConntrackError, strerror(errno));
            return -1;
        }
    }

    nfct_destroy(conntrack);
    nfct_close(ct_handle);
    return 0;
}


static RelayStream_get_attr_type RelayStream_get_attr_types[] = {
    { ATTR_TIMEOUT, -1 },
    { ATTR_ORIG_COUNTER_PACKETS, COUNTER_CALLER_PACKET_COUNT },
    { ATTR_ORIG_COUNTER_BYTES, COUNTER_CALLER_BYTE_COUNT },
    { ATTR_REPL_COUNTER_PACKETS, COUNTER_CALLEE_PACKET_COUNT },
    { ATTR_REPL_COUNTER_BYTES, COUNTER_CALLEE_BYTE_COUNT }
};


static PyGetSetDef RelayStream_getseters[] = {
    { "timeout", (getter) RelayStream_get_attr, (setter) RelayStream_set_timeout, "timeout value", &RelayStream_get_attr_types[0] },
    { "caller_packet_count", (getter) RelayStream_get_attr, 0, "caller packet count", &RelayStream_get_attr_types[1] },
    { "caller_byte_count", (getter) RelayStream_get_attr, 0, "caller byte count", &RelayStream_get_attr_types[2] },
    { "callee_packet_count", (getter) RelayStream_get_attr, 0, "callee packet count", &RelayStream_get_attr_types[3] },
    { "callee_byte_count", (getter) RelayStream_get_attr, 0, "callee byte count", &RelayStream_get_attr_types[4] },
    { NULL }  /* Sentinel */
};


static PyMemberDef RelayStream_members[] = {
    { "__dict__", T_OBJECT, offsetof(RelayStream, dict), 0 },
    { NULL } /* Sentinel */
};


static PyTypeObject RelayStream_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                   /* ob_size */
    "mediaproxy.interfaces.system._conntrack.RelayStream",         /* tp_name */
    sizeof(RelayStream),                 /* tp_basicsize */
    0,                                   /* tp_itemsize */
    (destructor) RelayStream_dealloc,    /* tp_dealloc */
    0,                                   /* tp_print */
    0,                                   /* tp_getattr */
    0,                                   /* tp_setattr */
    0,                                   /* tp_compare */
    0,                                   /* tp_repr */
    0,                                   /* tp_as_number */
    0,                                   /* tp_as_sequence */
    0,                                   /* tp_as_mapping */
    0,                                   /* tp_hash */
    0,                                   /* tp_call */
    0,                                   /* tp_str */
    0,                                   /* tp_getattro */
    0,                                   /* tp_setattro */
    0,                                   /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC, /* tp_flags */
    "RelayStream objects",               /* tp_doc */
    (traverseproc) RelayStream_traverse, /* tp_traverse */
    (inquiry) RelayStream_clear,         /* tp_clear */
    0,                                   /* tp_richcompare */
    0,                                   /* tp_weaklistoffset */
    0,                                   /* tp_iter */
    0,                                   /* tp_iternext */
    0,                                   /* tp_methods */
    RelayStream_members,                 /* tp_members */
    RelayStream_getseters,               /* tp_getset */
    0,                                   /* tp_base */
    0,                                   /* tp_dict */
    0,                                   /* tp_descr_get */
    0,                                   /* tp_descr_set */
    offsetof(RelayStream, dict),         /* tp_dictoffset */
    (initproc) RelayStream_init,         /* tp_init */
    0,                                   /* tp_alloc */
    RelayStream_new,                     /* tp_new */
};


static PyObject *
ExpireWatcher_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    ExpireWatcher *self;

    self = (ExpireWatcher *) type->tp_alloc(type, 0);
    if (self != NULL)
        self->ct_handle = NULL;

    return (PyObject *) self;
}


static void
ExpireWatcher_dealloc(ExpireWatcher *self)
{
    if (self->ct_handle != NULL)
        nfct_close(self->ct_handle);

    self->ob_type->tp_free((PyObject *) self);
}


static int
ExpireWatcher_init(ExpireWatcher *self, PyObject *args, PyObject *kwds)
{
    if (self->ct_handle != NULL)
        return 0;

    if (PyTuple_GET_SIZE(args) > 0) {
        PyErr_SetString(PyExc_TypeError, "This constructor takes no arguments");
        return -1;
    }
    if (kwds && PyDict_Size(kwds) > 0) {
        PyErr_SetString(PyExc_TypeError, "This constructor takes no arguments");
        return -1;
    }

    if ((self->ct_handle = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_DESTROY)) == NULL) {
        PyErr_SetString(ConntrackError, strerror(errno));
        return -1;
    }

    if (fcntl(nfct_fd(self->ct_handle), F_SETFL, O_NONBLOCK) < 0) {
        nfct_close(self->ct_handle);
        self->ct_handle = NULL;
        PyErr_SetString(ConntrackError, strerror(errno));
        return -1;
    }

    return 0;
}


/* TODO: Fix flow in this function */
static PyObject *
ExpireWatcher_read(ExpireWatcher *self)
{
    struct nf_conntrack *conntrack;
    RelayStream *relay_stream = RelayStream_head;
    int i;
    PyObject *retval;

    if (nfct_callback_register(self->ct_handle, NFCT_T_ALL, conntrack_cb_one, &conntrack)) {
        PyErr_SetString(ConntrackError, strerror(errno));
        return NULL;
    }

    if (nfct_catch(self->ct_handle) < 0) {
        nfct_callback_unregister(self->ct_handle);
        if (errno == EAGAIN) {
            Py_INCREF(Py_None);
            return Py_None;
        } else {
            PyErr_SetString(ConntrackError, strerror(errno));
            return NULL;
        }
    }
    nfct_callback_unregister(self->ct_handle);

    retval = Py_None;
    Py_INCREF(Py_None);

    if (nfct_get_attr_u8(conntrack, ATTR_ORIG_L3PROTO) != AF_INET)
        goto ExpireWatcher_read_none;
    if (nfct_get_attr_u8(conntrack, ATTR_REPL_L3PROTO) != AF_INET)
        goto ExpireWatcher_read_none;
    if (nfct_get_attr_u8(conntrack, ATTR_ORIG_L4PROTO) != IPPROTO_UDP)
        goto ExpireWatcher_read_none;
    if (nfct_get_attr_u8(conntrack, ATTR_REPL_L4PROTO) != IPPROTO_UDP)
        goto ExpireWatcher_read_none;

    for (relay_stream = RelayStream_head; relay_stream != NULL; relay_stream = relay_stream->next) {
        if (nfct_get_attr_u32(relay_stream->conntrack, ATTR_ORIG_IPV4_SRC) != nfct_get_attr_u32(conntrack, ATTR_ORIG_IPV4_SRC))
            continue;
        if (nfct_get_attr_u32(relay_stream->conntrack, ATTR_ORIG_PORT_SRC) != nfct_get_attr_u32(conntrack, ATTR_ORIG_PORT_SRC))
            continue;
        if (nfct_get_attr_u32(relay_stream->conntrack, ATTR_DNAT_IPV4) != nfct_get_attr_u32(conntrack, ATTR_REPL_IPV4_SRC))
            continue;
        if (nfct_get_attr_u32(relay_stream->conntrack, ATTR_DNAT_PORT) != nfct_get_attr_u32(conntrack, ATTR_REPL_PORT_SRC))
            continue;

        relay_stream->is_active = 0;
        if (relay_stream->prev == NULL)
            RelayStream_head = relay_stream->next;
        else
            relay_stream->prev->next = relay_stream->prev->next;
        if (relay_stream->next != NULL)
            relay_stream->next->prev = relay_stream->prev;
        for (i = 1; i < 5; i++)
            relay_stream->counter[RelayStream_get_attr_types[i].counter_index] = nfct_get_attr_u32(conntrack, RelayStream_get_attr_types[i].type);

        Py_DECREF(Py_None);
        Py_INCREF(relay_stream);
        retval = (PyObject *) relay_stream;
        break;
    }

ExpireWatcher_read_none:
    nfct_destroy(conntrack);
    return retval;
}


static PyObject *
ExpireWatcher_get_fd(ExpireWatcher *self, void *closure)
{
    return Py_BuildValue("i", nfct_fd(self->ct_handle));
}


static PyMethodDef ExpireWatcher_methods[] = {
    { "read", (PyCFunction) ExpireWatcher_read, METH_NOARGS, "Read one connection tracking expiration event" },
    { NULL }  /* Sentinel */
};


static PyGetSetDef ExpireWatcher_getseters[] = {
    { "fd", (getter) ExpireWatcher_get_fd, NULL, "file descriptor value", NULL },
    { NULL }  /* Sentinel */
};


static PyTypeObject ExpireWatcher_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                     /* ob_size */
    "mediaproxy.interfaces.system._conntrack.ExpireWatcher",  /* tp_name */
    sizeof(ExpireWatcher),                 /* tp_basicsize */
    0,                                     /* tp_itemsize */
    (destructor) ExpireWatcher_dealloc,    /* tp_dealloc */
    0,                                     /* tp_print */
    0,                                     /* tp_getattr */
    0,                                     /* tp_setattr */
    0,                                     /* tp_compare */
    0,                                     /* tp_repr */
    0,                                     /* tp_as_number */
    0,                                     /* tp_as_sequence */
    0,                                     /* tp_as_mapping */
    0,                                     /* tp_hash */
    0,                                     /* tp_call */
    0,                                     /* tp_str */
    0,                                     /* tp_getattro */
    0,                                     /* tp_setattro */
    0,                                     /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,               /* tp_flags */
    "ExpireWatcher objects",               /* tp_doc */
    0,                                     /* tp_traverse */
    0,                                     /* tp_clear */
    0,                                     /* tp_richcompare */
    0,                                     /* tp_weaklistoffset */
    0,                                     /* tp_iter */
    0,                                     /* tp_iternext */
    ExpireWatcher_methods,                 /* tp_methods */
    0,                                     /* tp_members */
    ExpireWatcher_getseters,               /* tp_getset */
    0,                                     /* tp_base */
    0,                                     /* tp_dict */
    0,                                     /* tp_descr_get */
    0,                                     /* tp_descr_set */
    0,                                     /* tp_dictoffset */
    (initproc) ExpireWatcher_init,         /* tp_init */
    0,                                     /* tp_alloc */
    ExpireWatcher_new,                     /* tp_new */
};


static PyObject *
ConntrackBlock_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    ConntrackBlock *self;

    self = (ConntrackBlock *) type->tp_alloc(type, 0);
    if (self != NULL) {
        self->done_init = 0;
        if ((self->entry = malloc(IPTC_FULL_SIZE)) == NULL) {
            Py_DECREF(self);
            PyErr_NoMemory();
            return NULL;
        }
    }

    return (PyObject *) self;
}


static void
ConntrackBlock_dealloc(ConntrackBlock *self)
{
    iptc_handle_t ct_handle;
    unsigned char matchmask[IPTC_FULL_SIZE];

    if (self->done_init)
        if ((ct_handle = iptc_init("raw")) != NULL) {
            memset(matchmask, 255, IPTC_FULL_SIZE);
            iptc_delete_entry("PREROUTING", self->entry, matchmask, &ct_handle);
            if (!iptc_commit(&ct_handle))
                iptc_free(&ct_handle);
        }

    free(self->entry);
    self->ob_type->tp_free((PyObject *) self);
}


static int
ConntrackBlock_init(ConntrackBlock *self, PyObject *args, PyObject *kwds)
{
    int port;
    char *address_string = NULL;
    struct in_addr address;
    iptc_handle_t ct_handle;
    struct ipt_entry_match *match;
    struct ipt_udp *match_udp;
    struct ipt_entry_target *target;

    if (self->done_init)
        return 0;

    if (kwds && PyDict_Size(kwds) > 0) {
        PyErr_SetString(PyExc_TypeError, "Keyword arguments not supported");
        return -1;
    }

    if (!PyArg_ParseTuple(args, "i|s", &port, &address_string))
        return -1;

    if (port < 0 || port > 65535) {
        PyErr_SetString(PyExc_ValueError, "UDP port should be between 0 and 65535");
        return -1;
    }
    if ((address_string != NULL) && !inet_aton(address_string, &address)) {
        PyErr_Format(PyExc_ValueError, "Invalid IP address given: \"%s\"", address_string);
        return -1;
    }

    memset(self->entry, 0, IPTC_FULL_SIZE);
    self->entry->ip.proto = IPPROTO_UDP;
    if (address_string != NULL) {
        self->entry->ip.dst = address;
        memset(&self->entry->ip.dmsk, 255, sizeof(struct in_addr));
    }
    self->entry->target_offset = IPTC_ENTRY_SIZE + IPTC_MATCH_SIZE;
    self->entry->next_offset = IPTC_FULL_SIZE;
    match = (void *) self->entry + IPTC_ENTRY_SIZE;
    match->u.user.match_size = IPTC_MATCH_SIZE;
    strcpy(match->u.user.name, "udp");
    match_udp = (struct ipt_udp *) &match->data;
    match_udp->spts[0] = 0;
    match_udp->spts[1] = 65535;
    match_udp->dpts[0] = match_udp->dpts[1] = port;
    target = (void *) match + IPTC_MATCH_SIZE;
    target->u.user.target_size = IPTC_TARGET_SIZE;
    strcpy(target->u.user.name, "NOTRACK");

    if ((ct_handle = iptc_init("raw")) == NULL) {
        PyErr_SetString(ConntrackError, iptc_strerror(errno));
        return -1;
    }

    if (!iptc_append_entry("PREROUTING", self->entry, &ct_handle)) {
        iptc_free(&ct_handle);
        PyErr_SetString(ConntrackError, iptc_strerror(errno));
        return -1;
    }

    if (!iptc_commit(&ct_handle)) {
        iptc_free(&ct_handle);
        PyErr_SetString(ConntrackError, iptc_strerror(errno));
        return -1;
    }

    self->done_init = 1;
    return 0;
}


static PyTypeObject ConntrackBlock_Type = {
    PyObject_HEAD_INIT(NULL)
    0,                                   /* ob_size */
    "mediaproxy.interfaces.system._conntrack.ConntrackBlock", /* tp_name */
    sizeof(ConntrackBlock),              /* tp_basicsize */
    0,                                   /* tp_itemsize */
    (destructor) ConntrackBlock_dealloc, /* tp_dealloc */
    0,                                   /* tp_print */
    0,                                   /* tp_getattr */
    0,                                   /* tp_setattr */
    0,                                   /* tp_compare */
    0,                                   /* tp_repr */
    0,                                   /* tp_as_number */
    0,                                   /* tp_as_sequence */
    0,                                   /* tp_as_mapping */
    0,                                   /* tp_hash */
    0,                                   /* tp_call */
    0,                                   /* tp_str */
    0,                                   /* tp_getattro */
    0,                                   /* tp_setattro */
    0,                                   /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT |
        Py_TPFLAGS_BASETYPE,             /* tp_flags */
    "ConntrackBlock objects",            /* tp_doc */
    0,                                   /* tp_traverse */
    0,                                   /* tp_clear */
    0,                                   /* tp_richcompare */
    0,                                   /* tp_weaklistoffset */
    0,                                   /* tp_iter */
    0,                                   /* tp_iternext */
    0,                                   /* tp_methods */
    0,                                   /* tp_members */
    0,                                   /* tp_getset */
    0,                                   /* tp_base */
    0,                                   /* tp_dict */
    0,                                   /* tp_descr_get */
    0,                                   /* tp_descr_set */
    0,                                   /* tp_dictoffset */
    (initproc) ConntrackBlock_init,      /* tp_init */
    0,                                   /* tp_alloc */
    ConntrackBlock_new,                  /* tp_new */
};


static PyMethodDef _conntrack_methods[] = {
    { NULL }  /* Sentinel */
};


PyMODINIT_FUNC
init_conntrack(void) 
{
    PyObject* module;

    if (PyType_Ready(&RelayStream_Type) < 0)
        return;
    if (PyType_Ready(&ExpireWatcher_Type) < 0)
        return;
    if (PyType_Ready(&ConntrackBlock_Type) < 0)
        return;

    module = Py_InitModule3("mediaproxy.interfaces.system._conntrack", _conntrack_methods, "Low level connection tracking manipulation for MediaProxy");

    Py_INCREF(&RelayStream_Type);
    PyModule_AddObject(module, "RelayStream", (PyObject *) &RelayStream_Type);
    Py_INCREF(&ExpireWatcher_Type);
    PyModule_AddObject(module, "ExpireWatcher", (PyObject *) &ExpireWatcher_Type);
    Py_INCREF(&ConntrackBlock_Type);
    PyModule_AddObject(module, "ConntrackBlock", (PyObject *) &ConntrackBlock_Type);

    ConntrackError = PyErr_NewException("mediaproxy.interfaces.system._conntrack.ConntrackError", NULL, NULL);
    Py_INCREF(ConntrackError);
    PyModule_AddObject(module, "ConntrackError", ConntrackError);
}

