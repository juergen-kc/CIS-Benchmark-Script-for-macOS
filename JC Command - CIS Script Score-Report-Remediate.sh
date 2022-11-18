hash=$(shasum -a 256 /tmp/Set_SecurityScoring.sh | awk '{print $1}')
    if [ $hash == 7deaf87b11930c1786cead45ba5590030167eb46cd8d3863534ad3038df455fe ] ;then
    echo "Script verified."
    else "Script not verified."
fi


/tmp/Set_SecurityScoring.sh

/tmp/CISBenchmarkScript-custom.sh -f

CISBenchmarkReportPath="/Library/Security/Reports"
CISBenchmarkReport="${CISBenchmarkReportPath}/CISBenchmarkReport.csv"

if grep -q Failed "$CISBenchmarkReport"; then
  echo 'Device needs remediation - executing' ;
  /tmp/CISBenchmarkScript-custom.sh -r # Remediating
else
    echo 'Device is compliant' ;
fi