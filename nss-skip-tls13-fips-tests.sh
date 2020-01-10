diff -up nss/tests/ssl/ssl.sh.skip-tls13-fips-mode nss/tests/ssl/ssl.sh
--- nss/tests/ssl/ssl.sh.skip-tls13-fips-mode	2019-05-16 10:52:35.926904215 +0200
+++ nss/tests/ssl/ssl.sh	2019-05-16 10:53:05.953281239 +0200
@@ -412,6 +412,12 @@ ssl_auth()
       echo "${testname}" | grep "TLS 1.3" > /dev/null
       TLS13=$?
 
+      if [ "${TLS13}" -eq 0 ] && \
+	 [ "$SERVER_MODE" = "fips" -o "$CLIENT_MODE" = "fips" ] ; then
+          echo "$SCRIPTNAME: skipping  $testname (non-FIPS only)"
+          continue
+      fi
+
       if [ "${CLIENT_MODE}" = "fips" -a "${CAUTH}" -eq 0 ] ; then
           echo "$SCRIPTNAME: skipping  $testname (non-FIPS only)"
       elif [ "$ectype" = "SNI" -a "$NORM_EXT" = "Extended Test" ] ; then
