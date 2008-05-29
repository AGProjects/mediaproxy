<?
class MediaSessions {
    /*
       connect to a mediaproxy dispatcher
       get media sessions and display them

    */

	var $dispatcher_port = 25061;
    var $sessions        = array();
    var $relays          = array();
    var $timeout         = 3;

    function MediaSessions ($dispatcher='',$filters=array(),$allowedDomains=array()) {

		global $userAgentImages;
        require("config/phone_images.php");

        $this->filters = $filters;
        $this->allowedDomains  = $allowedDomains;

		$this->userAgentImages = $userAgentImages;

        if (!strlen($dispatcher)) return false;

        list($ip,$port) = explode(":",$dispatcher);

        $this->dispatcher_ip = $ip;

        if ($port) $this->dispatcher_port = $port;

        return $this->getSessions($this->dispatcher_ip,$this->dispatcher_port);

    }

    function getSessions () {

        if (!$this->dispatcher_ip) return false;
        if (!$this->dispatcher_port) return false;

        if ($fp = fsockopen ($this->dispatcher_ip, $this->dispatcher_port, $errno, $errstr, $this->timeout)) {

            if (!count($this->allowedDomains)) {
               fputs($fp, "summary\r\n");
   
               while (!feof($fp)) {
                   $line  = fgets($fp);
   
                   if (preg_match("/^\r\n/",$line)) {
                       break;
                   }
   
                   $this->relays[] = json_decode($line);
               }
			}

            fputs($fp, "sessions\r\n");

            while (!feof($fp)) {
            	$line = fgets($fp);

                $this->sessions_json[] = $line;

                if (preg_match("/^\r\n/",$line)) {
                    break;
                }

				$line=json_decode($line);

                if (count($this->allowedDomains)) {
                    list($user1,$domain1)=explode("@",$line->from_uri);
                    list($user2,$domain2)=explode("@",$line->to_uri);
                    if (!in_array($domain1,$this->allowedDomains) && !in_array($domain2,$this->allowedDomains)) {
                        continue;
                    }
                }

                if (strlen($this->filters['user'])) {
                	$user=$this->filters['user'];
                    if (preg_match("/$user/",$line->from_uri) ||
                        preg_match("/$user/",$line->to_uri)
                        ) {
                		$this->sessions[] = $line;
                    }

                } else {
                	$this->sessions[] = $line;
                }

            }

        	fclose($fp);
            return true;

        } else {
            printf ("<p><font color=red>Error connecting to %s:%s: %s (%s) </font>\n",$this->dispatcher_ip,$this->dispatcher_port,$errstr,$errno);
            return false;
        }
    }

    function showSearch() {
        printf ("<form method=post action=%s>
        <input type=text name=user value='%s'>
        <input type=submit value='Search callers'>
        <p>
        ",
        $_SERVER['PHP_SELF'],
        $_REQUEST['user']
        );
    }

    function showHeader() {
        print "
        <html>
        <head>
          <title>Media sessions</title>
        </head>
        
        <body marginwidth=20 leftmargin=20 link=#000066 vlink=#006666 bgcolor=white>
        <style type=\"text/css\">
        <!--
        
        .border {
            border: 1px solid #999999;
            border-collapse: collapse;
        }
        
        .bordertb {
            border-top: 1px solid #999999;
            border-bottom: 1px solid #999999;
            border-collapse: collapse;
        }
        
        body {
            font-family: Verdana, Sans, Arial, Helvetica, sans-serif;
            font-size: 10pt;
            color: gray;
        }
        
        p {
            font-family: Verdana, Sans, Arial, Helvetica, sans-serif;
            font-size: 8pt;
            color: gray;
        }
        
        pre {
            font-family: Lucida Console, Courier;
            font-size: 10pt;
            color: black;
        }
        
        td {
            font-family: Verdana, Sans, Arial, Helvetica, sans-serif;
            font-size: 8pt;
            vertical-align: top;
            color: #444444;
        }
        
        th {
            font-family: Verdana, Sans, Arial, Helvetica, sans-serif;
            font-size: 8pt;
            vertical-align: bottom;
            color: black;
        }
        
        -->
        </style>
        ";
    }

    function showFooter() {
        print "<a href=http://www.ag-projects.com><img src=images/PoweredbyAGProjects.gif border=0></a>";
    	print "
        </body>
        </html>
        ";
    }

    function show() {

		$this->showHeader();

        print "<h1>Media sessions</h1>";

		$this->showSearch();

        if (!count($this->allowedDomains)) {
	        $this->showRelays();
        }

        $this->showSessions();

		$this->showFooter();
    }

    function showRelays() {

        print "
        <table border=0 class=border cellpadding=2 cellspacing=0>
          <tr bgcolor=#c0c0c0 class=border align=right>
            <th class=bordertb width=10px></th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Address</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Version</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Uptime</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Relayed traffic</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Sessions</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Streams</th>
            <th class=bordertb width=10px></th>
            <th class=bordertb>Status</th>
          </tr>";
    
        $i = 1;

        foreach ($this->relays as $relay) {

			unset($media_types);

            foreach ($relay->stream_count as $key => $value) {
                $media_types++;
            }

			if ($media_types > 1) {
                $streams = "<table border=0>";
    
                foreach ($relay->stream_count as $key => $value) {
                    $streams .= sprintf("<tr><td>%s</td><td>%s</td></tr>",$key,$value);
                }
    
                $streams .= "</table>";
            } else {
                foreach ($relay->stream_count as $key => $value) {
                	$streams=sprintf("%s %s",$key,$value);
                }
            }

        	printf ("
          	<tr class=border align=right>
                <td class=border>%d</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%s</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%s</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%s</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%s</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%d</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb valign=top>%s</td>
                <td class=bordertb width=10px></td>
                <td class=bordertb>%s</td>
              </tr>",
              $i,
              $relay->ip,
              $relay->version,
              $this->normalizeTime($relay->uptime),
              $this->normalizeTraffic($relay->bps_relayed),
              $relay->session_count,
              $streams,
              ucfirst($relay->status)
              );

             $i++;
        }

        print "
        </table>
        <br />
        ";
    }

    function showSessions () {
        print "
        <table border=0 cellpadding=2 cellspacing=0 class=border>
         <tr valign=bottom bgcolor=black>
          <th rowspan=2>&nbsp;</th>
          <th rowspan=2><font color=white>Callers</font></th>
          <th rowspan=2 colspan=2><font color=white>Phones</font></th>
          <th colspan=10 bgcolor=#393939><font color=white>Media Streams</font></th>
         </tr>
         <tr valign=bottom bgcolor=#afafaf>
          <th class=border><nobr>Caller address</nobr></th>
          <th class=border>Relay caller</th>
          <th class=border>Relay callee</th>
          <th class=border><nobr>Callee address</nobr></th>
          <th class=border>Status</th>
          <th class=border>Codec</th>
          <th class=border>Type</th>
          <th class=border>Duration</th>
          <th class=border>Bytes<br>Caller</th>
          <th class=border>Bytes<br>Called</th>
         </tr>";
    
            $i = 1;
            foreach ($this->sessions as $session) {
                $from = $session->from_uri;
                $to   = $session->to_uri;
                $fromAgent = $session->caller_ua;
                $toAgent   = $session->callee_ua;
                $fromImage = $this->getImageForUserAgent($fromAgent);
                $toImage = $this->getImageForUserAgent($toAgent);
                $sc = count($session->streams);

                    print "
         <tr valign=top class=border>
          <td class=border rowspan=$sc>$i</td>
          <td class=border rowspan=$sc>
            <nobr><b>From:</b> $from</nobr><br>
            <nobr><b>To:</b> $to</nobr><br>
          </td>
          <td class=border rowspan=$sc align=center>
            <img src=\"images/30/$fromImage\"
                 alt=\"$fromAgent\"
                 title=\"$fromAgent\"
                 ONMOUSEOVER='window.status=\"$fromAgent\";'
                 ONMOUSEOUT='window.status=\"\";'
                 border=0
            />
          </td>
          <td class=border rowspan=$sc align=center>
            <img src=\"images/30/$toImage\"
                 alt=\"$toAgent\"
                 title=\"$toAgent\"
                 ONMOUSEOVER='window.status=\"$toAgent\";'
                 ONMOUSEOUT='window.status=\"\";'
                 border=0
            />
          </td>";

                    $duration = $this->normalizeTime($session->duration);

                    foreach ($session->streams as $streamInfo) {
                        $status   = $streamInfo->status;

                        if ($status=="idle" || $status=='hold') {
                            $idletime = $this->normalizeTime($streamInfo->timeout_wait);
                            $status = sprintf("%s %s", $status, $idletime);
                        }

                        $caller = $streamInfo->caller_remote;
                        $callee = $streamInfo->callee_remote;
                        $relay_caller  = $streamInfo->caller_local;
                        $relay_callee  = $streamInfo->callee_local;

                        $codec  = $streamInfo->caller_codec;
                        $type   = $streamInfo->media_type;

                        if ($caller == '?.?.?.?:?') {
                            $caller = '&#150;';  // a dash
                            $align1 = 'center';
                        } else {
                            $align1 = 'left';
                        }
                        if ($callee == '?.?.?.?:?') {
                            $callee = '&#150;';  // a dash
                            $align2 = 'center';
                        } else {
                            $align2 = 'left';
                        }
                        if ($codec == 'Unknown')
                            $codec = '&#150;';   // a dash
                        if ($type == 'Unknown')
                            $type = '&#150;';    // a dash
                        $bytes_in1 = $this->normalizeBytes($streamInfo->caller_bytes);
                        $bytes_in2 = $this->normalizeBytes($streamInfo->callee_bytes);
                        print "
          <td class=border align=$align1>$caller</td>
          <td class=border align=left>$relay_caller</td>
          <td class=border align=left>$relay_callee</td>
          <td class=border align=$align2>$callee</td>

          <td class=border align=center><nobr>$status</nobr></td>
          <td class=border align=center>$codec</td>
          <td class=border align=center>$type</td>
          <td class=border align=right>$duration</td>
          <td class=border align=right>$bytes_in1</td>
          <td class=border align=right>$bytes_in2</td>
         </tr>";
                    }
                    $i++;
            }
            print "
         </table>
         <br />";

    }

    function normalizeBytes($bytes) {
        $mb = $bytes/1024/1024.0;
        $kb = $bytes/1024.0;
        if ($mb >= 0.95) {
            return sprintf("%.2fM", $mb);
        } else if ($kb >= 1) {
            return sprintf("%.2fk", $kb);
        } else {
            return sprintf("%d", $bytes);
        }
    }
    
    function normalizeTime($period) {
        $sec = $period % 60;
        $min = floor($period/60);
        $h   = floor($min/60);
        $min = $min % 60;
    
        if ($h >= 1) {
            return sprintf('%dh%02d\'%02d"', $h, $min, $sec);
        } else {
            return sprintf('%d\'%02d"', $min, $sec);
        }
    }
    
    function normalizeTraffic($traffic) {
        // input is in bytes/second
        $mb = $traffic/1024/1024.0;
        $kb = $traffic/1024.0;
        if ($mb >= 0.95) {
            return sprintf("%.2fMbps", $mb);
        } else if ($kb >= 1) {
            return sprintf("%.2fkbps",$kb);
        } else {
            return sprintf("%dbps",$traffic);
        }
    }
    
    function getImageForUserAgent($agent) {
    
        foreach ($this->userAgentImages as $agentRegexp => $image) {
            if (preg_match("/$agentRegexp/i", $agent)) {
                return $image;
            }
        }
    
        return "unknown.png";
    }

}
?>
