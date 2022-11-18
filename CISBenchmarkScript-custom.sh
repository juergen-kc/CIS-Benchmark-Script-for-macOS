#!/bin/zsh
# shellcheck shell=bash 

VERSION="1.5dev"
VERSIONDATE="2022-11-02"


####################################################################################################
#        License information
####################################################################################################
#
#        THE SCRIPTS ARE PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
#        INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY 
#        AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
#        I BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, 
#        OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
#        SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
#        INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
#        CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
#        ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
#        THE POSSIBILITY OF SUCH DAMAGE.
#
####################################################################################################
####################################################################################################
# 
#        Written by: Mischa van der Bent
#
#        DESCRIPTION
#        This script is inspired by the CIS Benchmark script of Jamf Professional Services 
#        https://github.com/jamf/CIS-for-macOS-Catalina-CP
#        And will look for a managed Configuration Profile (com.cis.benchmark.plist) and checks, 
#        remediation (if needend) and report.
#        The Security Score can be set with the Jamf Pro Custom Schema json file.
#        Reports are stored in /Library/Security/Reports.
# 
#        REQUIREMENTS
#        Compatible with Big Sure macOS 11.x
#        Compatible with Monterey macOS 12.x 
# 
####################################################################################################
####################################################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin

####################################################################################################
#        Directory/Path/Variables
####################################################################################################

CISBenchmarkReportPath="/Library/Security/Reports"
CISBenchmarkReport="${CISBenchmarkReportPath}/CISBenchmarkReport.csv"
plistlocation="/tmp/org_security_score.plist"
currentUser=$(scutil <<< "show State:/Users/ConsoleUser" | awk '/Name :/ { print $3 }')

####################################################################################################
#        Functions
####################################################################################################

function help() {
  echo
  echo "The following options are available:"
  echo 
  echo "	-f	--fullreport	Print Full Report"
  echo "	-h	--help		Displays this message or details on a specific verb"
  echo "	-r	--remediate	Enable Remediation"
  echo 
  echo "EXAMPLES"
  echo "    ./CISBenchmarkScript.sh -f"
  echo "            Run script to print Full Report"
  echo 
  echo "    ./CISBenchmarkScript.sh -r"
  echo "            Run script with Remediation enabled"
  echo
  echo "    ./CISBenchmarkScript.sh -rf"
  echo "            Run script with Remediation enabled and print Full Report "
  echo 
  exit
}

case $1 in 
    -f | --fullreport)
        argumentHeaderFunctionName="fullHeader"
        argumentReportFunctionName="fullReport"
        argumentRemediateVariable="disabled"
    ;;
    -fr | -rf | --fullreport-remediate | --remediate-fullreport)
        argumentHeaderFunctionName="fullHeader"
        argumentReportFunctionName="fullReport"
        argumentRemediateVariable="enabled"
    ;;
    -h | --help)
        help
    ;;
    -r | --remediate)
        argumentHeaderFunctionName="shortHeader"
        argumentReportFunctionName="shortReport"
        argumentRemediateVariable="enabled"
    ;;
    *)
        argumentHeaderFunctionName="shortHeader"
        argumentReportFunctionName="shortReport"
        argumentRemediateVariable="disabled"
    ;;
esac

function runAudit() {
	## Check if scoring file is present
	if [[ ! -f "${plistlocation}" ]]; then
		## No scoring file present, reporting all
		auditResult="1"
		scored=""
		echo "OrgScore ${audit}"
	else
		auditResult=$(defaults read "${plistlocation}" "${orgScore}" 2>&1)
		if [[ "${auditResult}" == "1" ]]; then
			scored="Scored"
			echo "OrgScore ${audit}"
		else
			scored="NOT Scored"
		fi
	fi
}

function runAsUser() {
	if [[ "${currentUser}" != "loginwindow" ]]; then
		uid=$(id -u "${currentUser}")
		launchctl asuser "$uid" sudo -u "${currentUser}" "$@"
	fi
}

function getPrefValue() { # $1: domain, $2: key
    osascript -l JavaScript << EndOfScript
        ObjC.import('Foundation');
        ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('$1').objectForKey('$2'))
EndOfScript
}

function getPrefValueNested() { # $1: domain, $2: key, $3: nestedkey
    osascript -l JavaScript << EndOfScript
        ObjC.import('Foundation');
        ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('$1').objectForKey('$2').objectForKey('$3'))
EndOfScript
}

function getPrefValuerunAsUser() { # $1: domain, $2: key
	runAsUser osascript -l JavaScript << EndOfScript
        ObjC.import('Foundation');
        ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('$1').objectForKey('$2'))
EndOfScript
}

function getPrefIsManaged() { # $1: domain, $2: key
    osascript -l JavaScript << EndOfScript
    ObjC.import('Foundation')
    ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('$1').objectIsForcedForKey('$2'))
EndOfScript
}

function getPrefIsManagedrunAsUser() { # $1: domain, $2: key
	runAsUser osascript -l JavaScript << EndOfScript
    ObjC.import('Foundation')
    ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('$1').objectIsForcedForKey('$2'))
EndOfScript
}

function CISBenchmarkReportFolder() {
	if [[ -d ${CISBenchmarkReportPath} ]]; then
		rm -Rf "${CISBenchmarkReportPath}"
		mkdir -p "${CISBenchmarkReportPath}"
		else
		mkdir -p "${CISBenchmarkReportPath}"
	fi
}

function shortHeader() {
	echo "Audit Number;Level;Scoring;Result;Managed;Method;Comments" >> "${CISBenchmarkReport}"
}

function fullHeader() {
	echo "Audit Number;Level;Scoring;Result;Managed;Preference domain;Option;Value;Method;Comments;Remediate" >> "${CISBenchmarkReport}"
}

function shortReport() {
	echo "${audit};${CISLevel};${scored};${result};${prefIsManaged};${method};${comment}" >> "${CISBenchmarkReport}"
}

function fullReport() {
	echo "${audit};${CISLevel};${scored};${result};${prefIsManaged};${appidentifier};${value};${prefValue};${method};${comment};${remediate}" >> "${CISBenchmarkReport}"
}

function printReport() {
	## Check if scoring file is present
	if [[ ! -f "${plistlocation}" ]]; then
		## No scoring file present, check arguments
		${argumentReportFunctionName}
	else
		reportSetting=$(defaults read "${plistlocation}" report 2>&1)
		if [[ "${reportSetting}" == "full" ]]; then
			fullReport
		else
			shortReport
		fi
	fi
}

function printReportHeaders() {
	## Check if scoring file is present
	if [[ ! -f "${plistlocation}" ]]; then
		## No scoring file present, check arguments
		${argumentHeaderFunctionName}
	else
		reportSetting=$(defaults read "${plistlocation}" report 2>&1)
		if [[ "${reportSetting}" == "full" ]]; then
			fullHeader
		else
			shortHeader
		fi
	fi
}

function runRemediate() {
	## Check if scoring file is present
	if [[ ! -f "${plistlocation}" ]]; then
		## No scoring file present, check arguments
		remediateResult="${argumentRemediateVariable}"
	else
		remediateResult=$(defaults read "${plistlocation}" "remediate" 2>&1)
		if [[ "${remediateResult}" == "enabled" ]]; then
			remediateResult="enabled"
		else
			remediateResult="disabled"
		fi
	fi
}

function emptyVariables() {
	prefIsManaged=""
	appidentifier=""
	value=""
	prefValue=""
	result=""
	method=""
	comment=""
	remediate=""
}

function killcfpref() {
	## Restart daemon responsible for prefrence caching
	echo "Killing cfprefs daemon "
	killall cfprefsd
}

####################################################################################################
#        Start Security report script
####################################################################################################

echo ""
echo "*** Security report started - $(date -u)"

# Check for macOS version
osVersion=$(sw_vers -productVersion)
buildVersion=$(sw_vers -buildVersion)
if [[ "$osVersion" = "10.15."* ]]; then
    echo "*** Current version - macOS Catalina ${osVersion} (${buildVersion})"
    echo "" 1>&2
elif [[ "$osVersion" = "11."* ]]; then
    echo "*** Current version - macOS Big Sur ${osVersion} (${buildVersion})"
    echo "" 1>&2
elif [[ "$osVersion" = "12."* ]]; then
    echo "*** Current version - macOS Monterey ${osVersion} (${buildVersion})"
    echo "" 1>&2
elif [[ "$osVersion" = "13."* ]]; then
    echo "*** Current version - macOS Ventura ${osVersion} (${buildVersion})"
    echo "*** NOTE: experimental support only - based on Monterey benchmarks"
    echo "" 1>&2
else
    echo ""
    echo "*** This script supports macOS Catalina, Big Sur, Monterey and Ventura only"
    echo
    echo "*** Quitting..."
    echo ""
    exit 1
fi

# Check for admin/root permissions
if [[ "$(id -u)" != "0" ]]; then
	echo "*** Script must be run as root, or have root privileges (ie. sudo)." 1>&2
	echo
	echo "*** Use -h --help for more instructions"
	echo
	echo "*** Quitting..."
	echo ""
	exit 1
fi

# Create report Folder/Files
CISBenchmarkReportFolder

# Create csv file headers
printReportHeaders

# check remediation
runRemediate

####################################################################################################
####################################################################################################
################################### DO NOT EDIT BELOW THIS LINE ####################################
####################################################################################################
####################################################################################################

CISLevel="1"
audit="1.1 Ensure All Apple-provided Software Is Current (Automated)"
orgScore="OrgScore1_1"
emptyVariables
method="Script"
remediate="Script > sudo /usr/sbin/softwareupdate --install --restart --recommended"
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	countAvailableSUS=$(/usr/bin/defaults read "/Library/Preferences/com.apple.SoftwareUpdate.plist" LastRecommendedUpdatesAvailable)
	if [[ "${countAvailableSUS}" == "0" ]]; then
		result="Passed"
		comment="Apple Software is Current"
	else
		result="Failed"
		comment="Available Updates: ${countAvailableSUS}, verify all Apple provided software is current"
	fi
fi
printReport

CISLevel="1"
audit="1.2 Ensure Auto Update Is Enabled (Automated)"
orgScore="OrgScore1_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SoftwareUpdate > AutomaticCheckEnabled=true"
	
	appidentifier="com.apple.SoftwareUpdate"
	value="AutomaticCheckEnabled"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Auto Update: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Auto Update: Disabled"		
		fi
	fi
fi
printReport

CISLevel="1"
audit="1.3 Ensure Download New Updates When Available is Enabled (Automated)"
orgScore="OrgScore1_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SoftwareUpdate > AutomaticDownload=true"

	appidentifier="com.apple.SoftwareUpdate"
	value="AutomaticDownload"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Download new updates when available: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Download new updates when available: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="1.4 Ensure Installation of App Update Is Enabled (Automated)"
orgScore="OrgScore1_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SoftwareUpdate > AutomaticallyInstallAppUpdates=true"

	appidentifier="com.apple.commerce"
	value="AutoUpdate"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="App updates: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="App updates: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="1.5 Ensure System Data Files and Security Updates Are Downloaded Automatically Is Enabled (Automated)"
orgScore="OrgScore1_5"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SoftwareUpdate > ConfigDataInstall=true - CriticalUpdateInstall=true "

	appidentifier="com.apple.SoftwareUpdate"
	value="ConfigDataInstall"
	value2="CriticalUpdateInstall"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefValue2=$(getPrefValue "${appidentifier}" "${value2}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="System data files and security update installs: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" && "${prefValue2}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" && "${prefValue2}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="System data files and security update installs: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="1.6 Ensure Install of macOS Updates Is Enabled (Automated)"
orgScore="OrgScore1_6"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SoftwareUpdate > AutomaticallyInstallMacOSUpdates=true)"

	appidentifier="com.apple.SoftwareUpdate"
	value="AutomaticallyInstallMacOSUpdates"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="macOS update installs: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="macOS update installs: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.1.1 Ensure Bluetooth Is Disabled If No Devices Are Paired (Automated)"
orgScore="OrgScore2_1_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -bool false"

	appidentifier="com.apple.controlcenter"
	value="Bluetooth"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")

	bluetoothEnabled=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
	comment="Paired Devices: ${prefValueAsUser}"
	if [[ "$bluetoothEnabled" == 0 ]]; then
		# bluetooth is off
		result="Passed"
	elif [[ "$bluetoothEnabled" == 1 ]] && [[ "${prefValueAsUser}" -gt 0 ]]; then
		# bluetooth is on, and there are paired devices
		result="Passed"
	else
		result="Failed"
		comment="Bluetooth On With No Paired Devices"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			defaults write /Library/Preferences/com.apple.Bluetooth ControllerPowerState -bool false
			killall -HUP bluetoothd
			# re-check
			# our remediation is turning Bluetooth off so no need to check for paired devices
			bluetoothEnabled=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
			if [[ "$bluetoothEnabled" == 0 ]]; then
				result="Passed After Remediation"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport


CISLevel="1"
audit="2.1.2 Ensure Show Bluetooth Status in Menu Bar Is Enabled (Automated)"
orgScore="OrgScore2_1_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo -u firstuser defaults -currentHost write com.apple.controlcenter.plist Bluetooth -int 18"

	appidentifier="com.apple.controlcenter"
	value="NSStatusItem Visible Bluetooth"
	# function check2_1_2 {
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")

	comment="Show Bluetooth status in menu bar: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValueAsUser}" == "true" ]]; then
		countPassed=$((countPassed + 1))
		result="Passed"
	else
		if [[ "${prefValueAsUser}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Enable Show Bluetooth status in menu bar"
			# Remediation
			if [[ "${remediateResult}" == "enabled" ]]; then
				su -l ${currentUser} -c "defaults -currentHost write com.apple.controlcenter.plist Bluetooth -int 18"
				killall ControlCenter
				# re-check
				sleep 1
				prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
				prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
				if [[ "${prefValueAsUser}" == "true" ]]; then
					result="Passed After Remediation"
					comment="Show Bluetooth status in menu bar: Enabled"
				else
					result="Failed After Remediation"
				fi
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.2.1 Ensure 'Set time and date automatically' Is Enabled (Automated)"
orgScore="OrgScore2_2_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.timed > TMAutomaticTimeOnlyEnabled=true"

	appidentifier="com.apple.timed"
	value="TMAutomaticTimeOnlyEnabled"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Time and date automatically: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "1" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "1" ]]; then
			result="Passed"
		else
			networkTime=$(systemsetup -getusingnetworktime)
			if [[ "${networkTime}" = "Network Time: On" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Time and date automatically: Disabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.2.2 Ensure time set is within appropriate limits (Automated)"
orgScore="OrgScore2_2_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/sbin/systemsetup -setusingnetworktime on && sudo /usr/sbin/systemsetup -setnetworktimeserver time.euro.apple.com"

	networkTimeserver=$(systemsetup -getnetworktimeserver 2>&1 | grep -c 'Network Time Server')
	printCLIResult=$(systemsetup -getnetworktimeserver)
	if [[ "$networkTimeserver" != "0" ]]; then
		result="Passed"
		comment="${printCLIResult}"
	else
		result="Failed"
		comment="Set Network Time Server"
		# Remediation
		/usr/sbin/systemsetup -setusingnetworktime on && sudo /usr/sbin/systemsetup -setnetworktimeserver time.euro.apple.com
		# re-check
		networkTimeserver=$(systemsetup -getnetworktimeserver 2>&1 | grep -c 'Network Time Server')
		printCLIResult=$(systemsetup -getnetworktimeserver)
		if [[ "$networkTimeserver" != "0" ]]; then
			result="Passed After Remediation"
			comment="${printCLIResult}"
		else
			result="Failed After Remediation"
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.3.1 Ensure an Inactivity Interval of 20 Minutes Or Less for the Screen Saver Is Enabled (Automated)"
orgScore="OrgScore2_3_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.screensaver > idleTime=1200"

	appidentifier="com.apple.screensaver"
	value="idleTime"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Inactivity interval for the screen saver: ${prefValueAsUser}"
	if [[ "${prefIsManaged}" == "true" && "${prefValueAsUser}" -le "1200" ]]; then
		result="Passed"
	else
		if [[ "${prefValueAsUser}" -le "1200" && "${prefValueAsUser}" != "" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Inactivity interval for the screen saver: ${prefValueAsUser}"
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.3.2 Ensure Screen Saver Corners Are Secure (Automated)"
orgScore="OrgScore2_3_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.dock > wvous-tl-corner=5, wvous-br-corner=10, wvous-bl-corner=13, wvous-tr-corner=0 - 5=Start Screen Saver, 10=Put Display to Sleep, 13=Lock Screen"

	appidentifier="com.apple.dock"
	value="wvous-bl-corner"
	value2="wvous-tl-corner"
	value3="wvous-tr-corner"
	value4="wvous-br-corner"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefValue2AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value2}")
	prefValue3AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value3}")
	prefValue4AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value4}")
	prefIsManaged=$(getPrefIsManagedrunAsUser "${appidentifier}" "${value}")
	prefIsManaged2=$(getPrefIsManagedrunAsUser "${appidentifier}" "${value2}")
	prefIsManaged3=$(getPrefIsManagedrunAsUser "${appidentifier}" "${value3}")
	prefIsManaged4=$(getPrefIsManagedrunAsUser "${appidentifier}" "${value4}")
	comment="Secure screen saver corners: enabled"
	if [[ "${prefIsManaged}" != "6" ]] || [[ "${prefIsManaged2}" != "6" ]] || [[ "${prefIsManaged3}" != "6" ]] || [[ "${prefIsManaged4}" != "6" ]]; then
		result="Passed"
	else
		result="Failed"
		comment="Secure screen saver corners: Disabled"
	fi
fi
value="${value}, ${value2}, ${value3}, ${value4}"
prefValue="${prefValueAsUser}, ${prefValue2AsUser}, ${prefValue3AsUser}, ${prefValue4AsUser}"
printReport

CISLevel="1"
audit="2.3.3 Audit Lock Screen and Start Screen Saver Tools (Manual)"
orgScore="OrgScore2_3_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Familiarise users with screen lock tools or corner to Start Screen Saver"
	
	appidentifier="com.apple.dock"
	value="wvous-bl-corner"
	value2="wvous-tl-corner"
	value3="wvous-tr-corner"
	value4="wvous-br-corner"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefValue2AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value2}")
	prefValue3AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value3}")
	prefValue4AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value4}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="End-users are familiar with screen lock tools or Hot Corners"
	if [[ "${prefIsManaged}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValueAsUser}" != "1" ]] || [[ "${prefValue2AsUser}" != "1" ]] || [[ "${prefValue3AsUser}" != "1" ]] || [[ "${prefValue4AsUser}" != "1" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Familiarise users with screen lock tools or corner to Start Screen Saver"
		fi
	fi
fi
value=""
prefValue=""
printReport

CISLevel="1"
audit="2.4.1 Ensure Remote Apple Events Is Disabled (Automated)"
orgScore="OrgScore2_4_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/sbin/systemsetup -setremoteappleevents off && sudo launchctl disable system/com.apple.AEServer"

	remoteAppleEvents=$(systemsetup -getremoteappleevents)
	if [[ "$remoteAppleEvents" == "Remote Apple Events: Off" ]]; then
		result="Passed"
		comment="Remote Apple Events: Disabled"
	else
		result="Failed"
		comment="Remote Apple Events: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			systemsetup -setremoteappleevents off
			launchctl disable system/com.apple.AEServer
			# re-check
			remoteAppleEvents=$(systemsetup -getremoteappleevents)
			if [[ "$remoteAppleEvents" == "Remote Apple Events: Off" ]]; then
				result="Passed After Remediation"
				comment="Remote Apple Events: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.2 Ensure Internet Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.MCX > forceInternetSharingOff=true"

	comment="Internet Sharing: Disabled"
	if [[ -e /Library/Preferences/SystemConfiguration/com.apple.nat.plist ]]; then
		natAirport=$(/usr/libexec/PlistBuddy -c "print :NAT:AirPort:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist > /dev/null 2>&1)
		natEnabled=$(/usr/libexec/PlistBuddy -c "print :NAT:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist > /dev/null 2>&1)
		natPrimary=$(/usr/libexec/PlistBuddy -c "print :NAT:PrimaryInterface:Enabled" /Library/Preferences/SystemConfiguration/com.apple.nat.plist > /dev/null 2>&1)
		forwarding=$(sysctl net.inet.ip.forwarding 2>&1| awk '{ print $NF }')
		if [[ "$natAirport" != "1" ]] || [[ "$natEnabled" != "1" ]] || [[ "$natPrimary" != "1" ]] || [[ "$forwarding" != "1" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Internet Sharing: Enabled"
		fi
	fi
	result="Passed"
fi
printReport

CISLevel="1"
audit="2.4.3 Ensure Screen Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl disable system/com.apple.screensharing"
	
	screenSharing=$(launchctl print-disabled system | grep -c '"com.apple.screensharing" => true')
	if [[ "$screenSharing" == "1" ]]; then
		result="Passed"
		comment="Screen Sharing: Disabled"
	else
		result="Failed"
		comment="Screen Sharing: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo launchctl disable system/com.apple.screensharing
			# re-check
			screenSharing=$(launchctl print-disabled system | grep -c '"com.apple.screensharing" => true')
			if [[ "$screenSharing" == "1" ]]; then
				result="Passed After Remediation"
				comment="Screen Sharing: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.4 Ensure Printer Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/sbin/cupsctl --no-share-printers"

	printerSharing=$(cupsctl | grep "share_printers")
	if [[ "${printerSharing}" == "_share_printers=0" ]]; then
		result="Passed"
		comment="Printer Sharing: Disabled"
	else
		result="Failed"
		comment="Printer Sharing: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo /usr/sbin/cupsctl --no-share-printers
			# re-check
			printerSharing=$(cupsctl | grep "share_printers")
			if [[ "${printerSharing}" == "_share_printers=0" ]]; then
				result="Passed After Remdiatio"
				comment="Printer Sharing: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.5 Ensure Remote Login Is Disabled (Automated)"
orgScore="OrgScore2_4_5"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/sbin/systemsetup -setremotelogin off"
	
	screenSharing=$(systemsetup -getremotelogin | grep -c 'Remote Login: Off')
	if [[ "$screenSharing" == "1" ]]; then
		result="Passed"
		comment="Remote Login: Disabled"
	else
		result="Failed"
		comment="Remote Login: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			echo yes | systemsetup -setremotelogin off > /dev/null 2>&1
			# re-check
			screenSharing=$(systemsetup -getremotelogin | grep -c 'Remote Login: Off')
			if [[ "$screenSharing" == "1" ]]; then
				result="Passed After Remediation"
				comment="Remote Login: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi	
	fi
fi
printReport

CISLevel="1"
audit="2.4.6 Ensure DVD or CD Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_6"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist"
	discSharing=$(launchctl list | grep -Ec ODSAgent)
	if [[ "${discSharing}" == "0" ]]; then
		result="Passed"
		comment="DVD or CD Sharing: Disabled"
	else
		result="Failed"
		comment="DVD or CD Sharing: Enabled"
	# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist
			# re-check
			discSharing=$(launchctl list | grep -Ec ODSAgent)
			if [[ "${discSharing}" == "0" ]]; then
				result="Passed After Remediation"
				comment="DVD or CD Sharing: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
		
	fi
fi
printReport

CISLevel="1"
audit="2.4.7 Ensure Bluetooth Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_7"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo -u 'CURRENT_USER' defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false"

	appidentifier="com.apple.Bluetooth"
	value="PrefKeyServicesEnabled"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Bluetooth Sharing: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValueAsUser}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValueAsUser}" == "false" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Bluetooth Sharing: Enabled"
		# Remediation
			if [[ "${remediateResult}" == "enabled" ]]; then
				sudo -u ${currentUser} defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
				# re-check
				prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
				if [[ "${prefValueAsUser}" == "false" ]]; then
					result="Passed After Remediation"
				else
					result="Failed After Remediation"
				fi
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.8 Ensure File Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_8"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl disable system/com.apple.smbd"
	smbEnabled=$(launchctl print-disabled system | grep -c '"com.apple.smbd" => false')
	if [[ "${smbEnabled}" == "0" ]]; then
		result="Passed"
		comment="File Sharing: Disabled"
	else
		result="Failed"
		comment="File Sharing: Enabled"
	# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo launchctl disable system/com.apple.smbd
			killcfpref
			# re-check
			smbEnabled=$(launchctl print-disabled system | grep -c '"com.apple.smbd" => false')
			if [[ "${smbEnabled}" == "0" ]]; then
				result="Passed After Remediation"
				comment="File Sharing: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.9 Ensure Remote Management Is Disabled (Automated)"
orgScore="OrgScore2_4_9"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop"
	screenSharing=$(runAsUser launchctl list | grep com.apple.RemoteDesktop.agent | awk '{ print $1 }')
	if [[ "$screenSharing" == "-" ]]; then
		result="Passed"
		comment="Remote Management: Disabled"
	else
		result="Failed"
		comment="Remote Management: Enabled"
	# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
		sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop
		# re-check
			screenSharing=$(runAsUser launchctl list | grep com.apple.RemoteDesktop.agent | awk '{ print $1 }')
			if [[ "$screenSharing" == "-" ]]; then	
				result="Passed After Remediation"
				comment="Remote Management: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.4.10 Ensure Content Caching Is Disabled (Automated)"
orgScore="OrgScore2_4_10"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.applicationaccess > allowContentCaching=false"

	appidentifier="com.apple.applicationaccess"
	value="allowContentCaching"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Content Caching: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		countPassed=$((countPassed + 1))
		result="Passed"
	else
		if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
		else
			contentCacheStatus=$(AssetCacheManagerUtil status 2>&1 | grep -c "Activated: true")
			if [[ "${contentCacheStatus}" == 0 ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Content Caching: Enabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.11 Ensure AirDrop Is Disabled (Automated)"
orgScore="OrgScore2_4_11"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	if [[ "$osVersion" == "12."* ]]; then
		method="Profile"
		remediate="Configuration profile - payload > com.apple.NetworkBrowser > DisableAirDrop=true"

		appidentifier="com.apple.NetworkBrowser"
		value="DisableAirDrop"
		prefValue=$(getPrefValue "${appidentifier}" "${value}")
		prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
		comment="AirDrop: Disabled"
			if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			if [[ "${prefValue}" == "true" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="AirDrop: Enabled"
			fi
		fi
	else
		method="Profile"
		remediate="Configuration profile - payload > com.apple.applicationaccess > allowAirDrop=false"

		appidentifier="com.apple.applicationaccess"
		value="allowAirDrop"
		prefValue=$(getPrefValue "${appidentifier}" "${value}")
		prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
		comment="AirDrop: Disabled"
		if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
			result="Passed"
		else
			if [[ "${prefValue}" == "false" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="AirDrop: Enabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.4.12 Ensure Media Sharing Is Disabled (Automated)"
orgScore="OrgScore2_4_12"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.preferences.sharing.SharingPrefsExtension > homeSharingUIStatus=0 > legacySharingUIStatus=0 > mediaSharingUIStatus=0"

	appidentifier="com.apple.preferences.sharing.SharingPrefsExtension"
	value="homeSharingUIStatus"
	value2="legacySharingUIStatus"
	value3="mediaSharingUIStatus"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefValue2AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value2}")
	prefValue3AsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value3}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Media Sharing: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValueAsUser}" == "0" ]] && [[ "${prefValue2AsUser}" == "0" ]] && [[ "${prefValue3AsUser}" == "0" ]]; then
		result="Passed"
	else 
		if [[ "${prefValueAsUser}" == "0" ]] && [[ "${prefValue2AsUser}" == "0" ]] && [[ "${prefValue3AsUser}" == "0" ]]; then
			result="Passed"
		elif
			[[ "${prefValueAsUser}" == "" ]] && [[ "${prefValue2AsUser}" == "" ]] && [[ "${prefValue3AsUser}" == "" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Media Sharing: Enabled"
			fi
	fi
fi
value="${value}, ${value2}, ${value3}"
prefValue="${prefValueAsUser}, ${prefValue2AsUser}, ${prefValue3AsUser}"
printReport

CISLevel="1"
audit="2.4.13 Ensure AirPlay Receiver Is Disabled (Automated)"
orgScore="OrgScore2_4_13"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.controlcenter > AirplayRecieverEnabled=false"

	appidentifier="com.apple.controlcenter"
	value="AirplayRecieverEnabled"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Airplay Receiver: Disabled"
	if [[ "$osVersion" != "12."* ]]; then
	result="Not Applicable"
	comment="Benchmark not compactible with OS Version" 
	else
		if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		result="Passed"
		else
			if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
			else
			result="Failed"
			comment="Airplay Receiver: Enabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.5.1.1 Ensure FileVault Is Enabled (Automated)"
orgScore="OrgScore2_5_1_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.MCX.FileVault2 > Enable=On"

	appidentifier="com.apple.MCX.FileVault2"
	value="Enable"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="FileVault: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "On" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "On" ]]; then
			result="Passed"
		else
			filevaultEnabled=$(fdesetup status | grep -c "FileVault is On.")
			if [[ "$filevaultEnabled" == "1" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="FileVault: Disabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.5.1.2 Ensure all user storage APFS volumes are encrypted (Manual)"
orgScore="OrgScore2_5_1_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Ensure all user storage APFS Volumes are encrypted"

	apfsyes=$(diskutil ap list)
	if [[ "$apfsyes" != "No APFS Containers found" ]]; then
		startupEncrypted=$(diskutil info / | awk '/FileVault/ {print $2}')
		if [[ "$startupEncrypted" == "Yes" ]]; then
			result="Passed"
			comment="Startup Volume: Encrypted"
		else
			result="Failed"
			comment="Ensure all user storage APFS Volumes are encrypted"
		fi 
	else 
		result="Not applicable"
		comment="Volumes: CoreStorage"
	fi
fi
printReport

CISLevel="1"
audit="2.5.1.3 Ensure all user storage CoreStorage volumes are encrypted (Manual)"
orgScore="OrgScore2_5_1_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Ensure all user CoreStorage volumes encrypted"

	coreStorage=$(diskutil cs list)
	if [[ "$coreStorage" != "No CoreStorage logical volume groups found" ]]; then
		# get Logical Volume Family
		lvf=$(diskutil cs list | grep "Logical Volume Family" | awk '/Logical Volume Family/ {print $5}')
		# Check encryption status is complete
		EncryptStatus=$(diskutil cs "$lfv" | awk '/Conversion Status/ {print $3}')
		if [[ "$EncryptStatus" != "Complete" ]]; then
			result="Failed"
			comment="Ensure all user CoreStorage volumes encrypted"
		else 
			result="Passed"
			comment="All user CoreStorage volumes encrypted"
		fi
	else 
		result="Not Applicable"
		comment="No CoreStorage logical volume groups found"
	fi
fi
printReport

CISLevel="1"
audit="2.5.2.1 Ensure Gatekeeper is Enabled (Automated)"
orgScore="OrgScore2_5_2_1"
emptyVariables
method="Profile"
remediate="Configuration profile - payload > com.apple.systempolicy.control > EnableAssessment=true "
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	checkGatekeeperStatus=$(/usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled")
	if [[ "${checkGatekeeperStatus}" == "1" ]]; then
		result="Passed"
		comment="Gatekeeper Enabled"
	else
		result="Failed"
		comment="Gatekeeper Not Enabled"
	fi
fi
printReport

CISLevel="1"
audit="2.5.2.2 Ensure Firewall Is Enabled (Automated)"
orgScore="OrgScore2_5_2_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.security.firewall > EnableFirewall=true"

	appidentifier="com.apple.security.firewall"
	value="EnableFirewall"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Firewall: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "1" ]]; then
			result="Passed"
		else	
			firewallState=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>&1)
			if [[ "$firewallState" = "1" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Firewall: Disabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.5.2.3 Ensure Firewall Stealth Mode Is Enabled (Automated)"
orgScore="OrgScore2_5_2_3"
emptyVariables
# Verify organizational score
runAudit
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.security.firewall > EnableStealthMode=true"

	appidentifier="com.apple.security.Firewall"
	value="EnableStealthMode"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Firewall Stealth Mode: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			stealthEnabled=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode | grep -c "Stealth mode enabled")
			if [[ "$stealthEnabled" == "1" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Firewall Stealth Mode: Disabled"
			fi
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.5.3 Ensure Location Services Is Enabled (Automated)"
orgScore="OrgScore2_5_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool true && sudo /bin/launchctl kickstart -k system/com.apple.locationd"
	
	locationServices=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled 2>&1)
	if [[ "${locationServices}" != "0" ]]; then
		result="Passed"
		comment="Location Services: Enabled"
	else 
		result="Failed"
		comment="Location Services: Disabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool true && sudo /bin/launchctl kickstart -k system/com.apple.locationd
			# re-check
			locationServices=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.plist LocationServicesEnabled 2>&1)
			if [[ "${locationServices}" != "0" ]]; then
				result="Passed After Remediation"
				comment="Location Services: Enabled"
			else 
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.5.4 Audit Location Services Access (Manual)"
orgScore="OrgScore2_5_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Disable unnecessary applications from accessing location services"
	
	locationServices=$(defaults read /var/db/locationd/clients.plist 2>&1 | grep -c "Authorized")
	if [[ "${locationServices}" != "0" ]]; then
		result="Notice"
		comment="${locationServices} applications can accessing location services"
	else 
		result="Passed"
		comment="No Location Services Access"
	fi
fi
printReport

CISLevel="2"
audit="2.5.5 Ensure Sending Diagnostic and Usage Data to Apple Is Disabled (Automated)"
orgScore="OrgScore2_5_5"
emptyVariables
# Verify organizational score
runAudit
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.SubmitDiagInfo > AutoSubmit=false - payload > com.apple.applicationaccess > allowDiagnosticSubmission=false"

	appidentifier="com.apple.SubmitDiagInfo"
	value="AutoSubmit"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Sending diagnostic and usage data to Apple: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
		else
			diagnosticEnabled=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit)
			if [[ "${diagnosticEnabled}" == "0" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Sending diagnostic and usage data to Apple: Enabled"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.5.6 Ensure Limit Ad Tracking Is Enabled (Automated)"
orgScore="OrgScore2_5_6"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.AdLib > allowApplePersonalizedAdvertising=false"

	appidentifier="com.apple.AdLib"
	value="allowApplePersonalizedAdvertising"
	prefValueAsUser=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Limited Ad Tracking: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValueAsUser}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValueAsUser}" == "false" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Limited Ad Tracking: Enabled"
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.6.1.1 Audit iCloud Configuration (Manual)"
orgScore="OrgScore2_6_1_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Use a profile to disable services where organizationally required"

	over500=$(dscl . list /Users UniqueID 2>&1 | /usr/bin/awk '$2 > 500 { print $1 }')
	for EachUser in $over500 ;
	do
		UserHomeDirectory=$(dscl . -read /Users/"$EachUser" NFSHomeDirectory 2>&1 | /usr/bin/awk '{print $2}')
		CheckForiCloudAccount=$(defaults read "$UserHomeDirectory/Library/Preferences/MobileMeAccounts" Accounts 2>&1 | /usr/bin/grep -c 'AccountDescription = iCloud')
		# If client fails, then note category in audit file
		if [[ "${CheckForiCloudAccount}" -gt "0" ]] ; then
			result="Failed"
			comment="${CheckForiCloudAccount} iCloud account(s) configured"
		else
			result="Passed"
			comment="no iCloud account(s) configured"
		fi
	done
fi
printReport

CISLevel="2"
audit="2.6.1.2 Audit iCloud Keychain (Manual)"
orgScore="OrgScore2_6_1_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.applicationaccess) allowCloudKeychainSync=false"

	appidentifier="com.apple.applicationaccess"
	value="allowCloudKeychainSync"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="iCloud keychain: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
			else
			result="Failed"
			comment="iCloud keychain: Enabled"
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.6.1.3 Audit iCloud Drive (Manual)"
orgScore="OrgScore2_6_1_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.applicationaccess > allowCloudDocumentSync=false"

	appidentifier="com.apple.applicationaccess"
	value="allowCloudDocumentSync"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="iCloud Drive: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="iCloud Drive: Enabled"
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.6.1.4 Ensure iCloud Drive Document and Desktop Sync is Disabled (Automated)"
orgScore="OrgScore2_6_1_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.applicationaccess > allowCloudDesktopAndDocuments=false"

	appidentifier="com.apple.applicationaccess"
	value="allowCloudDesktopAndDocuments"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="iCloud Drive Document and Desktop sync: Disabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "false" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "false" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="iCloud Drive Document and Desktop sync: Enabled"
		fi
	fi
fi
printReport

CISLevel="2"
audit="2.7.1 Ensure Backup Up Automatically is Enabled (Automated)"
orgScore="OrgScore2_7_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.TimeMachine > AutoBackup=true"

	appidentifier="com.apple.TimeMachine"
	value="AutoBackup"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Backup Up: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Backup Up: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.7.2 Ensure Time Machine Volumes Are Encrypted (Automated)"
orgScore="OrgScore2_7_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > Set encryption through Disk Utility or diskutil in terminal"
	
	tmDestination=$(tmutil destinationinfo | grep -i NAME | awk '{print $2}')
	tmDrives=$(tmutil destinationinfo | grep -c "NAME")
	tmVolumeEncrypted=$(diskutil info "${tmDestination}" 2>&1 | grep -c "Encrypted: Yes")
	if [[ "${tmDrives}" -gt "0" && "${tmVolumeEncrypted}" -gt "0" ]]; then
		result="Passed"
		comment="Time Machine Volumes: Encrypted"
	else 
		if [[ "${tmDrives}" == "0" ]]; then
			result="Passed"
			comment="No Time Machine Volumes available"
		else
			result="Failed"
			comment="Time Machine Volumes: Unencrypted"
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.8 Ensure Wake for Network Access Is Disabled (Automated)"
orgScore="OrgScore2_8"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/bin/pmset -a womp 0"
	
	wakeNetwork=$(pmset -g custom | awk '/womp/ { sum+=$2 } END {print sum}')
	if [[ "${wakeNetwork}" == "0" ]]; then
		result="Passed"
		comment="Wake for network access: Disabled"
	else
		result="Failed"
		comment="Wake for network access: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			pmset -a womp 0
		# re-check
			wakeNetwork=$(pmset -g custom | awk '/womp/ { sum+=$2 } END {print sum}')
			if [[ "${wakeNetwork}" == "0" ]]; then
				result="Passed After Remediation"
				comment="Wake for network access: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.9 Ensure Power Nap Is Disabled (Automated)"
orgScore="OrgScore2_9"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/bin/pmset -a powernap 0"
	
	powerNap=$(pmset -g custom | awk '/powernap/ { sum+=$2 } END {print sum}')
	if [[ "${powerNap}" == "0" ]]; then
		result="Passed"
		comment="Power Nap: Enabled"
	else 
		result="Failed"
		comment="Power Nap: Disabled"
	# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo /usr/bin/pmset -a powernap 0
			# re-check
			powerNap=$(pmset -g custom | awk '/powernap/ { sum+=$2 } END {print sum}')
			if [[ "${powerNap}" == "0" ]]; then
				result="Passed After Remediation"
				comment="Power Nap: Enabled"
			else 
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.10 Ensure Secure Keyboard Entry terminal.app is Enabled (Automated)"
orgScore="OrgScore2_10"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.Terminal > SecureKeyboardEntry=true"

	appidentifier="com.apple.Terminal"
	value="SecureKeyboardEntry"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Secure Keyboard Entry in terminal.app: Enabled"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Secure Keyboard Entry in terminal.app: Disabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="2.11 Ensure EFI Version Is Valid and Checked Regularly (Automated)"
orgScore="OrgScore2_11"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Manual"
	remediate="Manual > If EFI does not pass the integrity check you may send a report to Apple. Backing up files and clean installing a known good Operating System and Firmware is recommended."
	
	comment="EFI version: Valid"
	# Check for Apple Silicon
	if [[ "$(sysctl -in hw.optional.arm64)" == '1' ]]; then
	result="Not Applicable"
	comment="Apple Silicon"
	else
	# Check for T2 chip.
	securityChip=$(system_profiler SPiBridgeDataType 2>&1 | grep -c 'Model Name: Apple T2 Security Chip')
		if [[ "${securityChip}" == "1" ]]; then
			t2Check=$(launchctl list | grep -c com.apple.driver.eficheck)
			if [[ "$t2Check" == "1" ]] then
			result="Passed"
			else
				result="Failed"
				comment="EFI version: Invalid"
			fi
		else
			efiStatus=$(/usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | grep -c "No changes detected")
			if [[ "${efiStatus}" -gt 0 ]]; then
				result="Passed"
			else
				result="Failed"
				comment="EFI version: Invalid"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="3.1 Ensure Security Auditing Is Enabled (Automated)"
orgScore="OrgScore3_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist"
	
	auditdEnabled=$(launchctl list 2>&1 | grep -c auditd)
	if [[ "${auditdEnabled}" -gt "0" ]]; then
		result="Passed"
		comment="Security auditing: Enabled"
	else 
		result="Failed"
		comment="Security auditing: Disabled"
	# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist
		# re-check
			auditdEnabled=$(launchctl list 2>&1 | grep -c auditd)
			if [[ "${auditdEnabled}" -gt "0" ]]; then
				result="Passed After Remediation"
				comment="Security auditing: Enabled"
			else 
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="2"
audit="3.2 Ensure Security Auditing Flags Are Configured Per Local Organizational Requirements (Automated)"
orgScore="OrgScore3_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control /usr/sbin/audit -s"

	auditFlags="$(grep -c "^flags:" /etc/security/audit_control)"
	if [[ "${auditFlags}" == "1" ]]; then
		result="Passed"
		comment="Security Auditing Flags: Enabled"
	else 
		result="Failed"
		comment="Security Auditing Flags: Disabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			/usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control /usr/sbin/audit -s
			#re-check
			auditFlags="$(grep -c "^flags:" /etc/security/audit_control)"
			if [[ "${auditFlags}" == "1" ]]; then
				result="Passed After Remediation"
				comment="Security Auditing Flags: Enabled"
			else 
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="3.3 Ensure install.log Is Retained for 365 or More Days and No Maximum Size (Automated)"
orgScore="OrgScore3_3"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > add 'ttl=365' to /etc/asl/com.apple.install"

	installRetention="$(grep -c ttl=365 /etc/asl/com.apple.install)"
	if [[ "${installRetention}" = "1" ]]; then
		result="Passed"
		comment="Retain install.log: 365 or more days"
	else 
		result="Failed"
		comment="Retain install.log: Less than 365 days"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			mv /etc/asl/com.apple.install{,.old}
			sed '$s/$/ ttl=365/' /etc/asl/com.apple.install.old > /etc/asl/com.apple.install
			chmod 644 /etc/asl/com.apple.install
			chown root:wheel /etc/asl/com.apple.install			
			#re-check
			installRetention="$(grep -c ttl=365 /etc/asl/com.apple.install)"
			if [[ "${installRetention}" = "1" ]]; then
				result="Passed After Remediation"
				comment="Retain install.log: 365 or more days"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="3.4 Ensure Security Auditing Retention Is Enabled (Automated)"
orgScore="OrgScore3_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational scorse is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > add 'expire-after:60d OR 1G' to /etc/security/audit_control"

	auditRetention="$(grep -c "expire-after:60d OR 1G" /etc/security/audit_control)"	
	if [[  "${auditRetention}" == "1" ]]; then
		result="Passed"
		comment="Security auditing retention: Configured"
	else 
		result="Failed"
		comment="Security auditing retention: Unconfigured"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			cp /etc/security/audit_control /etc/security/audit_control_old
			oldExpireAfter=$(grep -E "expire-after" /etc/security/audit_control)
			sed "s/${oldExpireAfter}/expire-after:60d OR 1G/g" /etc/security/audit_control_old > /etc/security/audit_control
			chmod 400 /etc/security/audit_control
			chown root:wheel /etc/security/audit_control
			# re-check
			auditRetention="$(grep -c "expire-after:60d OR 1G" /etc/security/audit_control)"	
			if [[  "${auditRetention}" == "1" ]]; then
				result="Passed After Remediation"
				comment="Security auditing retention: Configured"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="3.5 Ensure Access to Audit Records Is Controlled (Automated)"
orgScore="OrgScore3_5"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo chown -R root $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')"

	controlAccess=$(/usr/bin/grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
	accessCheck=$(find "${controlAccess}" | awk '{s+=$3} END {print s}')
	ownership=$(ls -ld /etc/security/audit_control | cut -d' ' -f4 -f6)
	if [[ "${accessCheck}" == "0" ]] && [[ "${ownership}" == "root wheel" ]]; then
		result="Passed"
		comment="Control access to audit records: Correct ownership"
	else 
		result="Failed"
		comment="Control access to audit records: Incorrect ownership"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			chown -R root:wheel /var/audit
			chmod -R 400 /var/audit
			chown root:wheel /etc/security/audit_control
			chmod 400 /etc/security/audit_control
			# re-check
			controlAccess=$(grep '^dir' /etc/security/audit_control | awk -F: '{print $2}')
			accessCheck=$(find "${controlAccess}" | awk '{s+=$3} END {print s}')
			ownership=$(ls -ld /etc/security/audit_control | cut -d' ' -f4 -f6)
			if [[ "${accessCheck}" == "0" ]] && [[ "${ownership}" == "root wheel" ]]; then
				result="Passed After Remediation"
				comment="Control access to audit records: Correct ownership"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="3.6 Ensure Firewall is configured to log (Automated)"
orgScore="OrgScore3_6"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	if [[ "$osVersion" == "12."* ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.security.firewall > EnableLogging=true LoggingOption=detail"

	appidentifier="com.apple.security.firewall"
	value="EnableLogging"
	value2="LoggingOption"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefValue2=$(getPrefValue "${appidentifier}" "${value2}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Firewall logging: Enabled"
		if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" && "${prefValue2}" == "detail" ]]; then
			result="Passed"
		else
			if [[ "${prefValue}" == "true" && "${prefValue2}" == "detail" ]]; then
				result="Passed"
			else
				result="Failed"
				comment="Firewall logging: Disabled"
			fi
		fi
else
	method="Script"
	remediate="Script > sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on"

	FWlog=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | grep -c "Log mode is on")
		if [[ "$FWlog" = "1" ]]; then
			result="Passed"
			comment="Firewall logging: Enabled"
		else 
			result="Failed"
			comment="Firewall logging: Disabled"
			# Remediation
			if [[ "${remediateResult}" == "enabled" ]]; then
				/usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on
				# re-check
				FWlog=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | grep -c "Log mode is on")
				printCLIResult=$(systemsetup -getnetworktimeserver)
				if [[ "$FWlog" = "1" ]]; then
					result="Passed After Remediation"
					comment="Firewall logging: Enabled"
				else
					result="Failed After Remediation"
					comment="Firewall logging: Disabled"
				fi
			fi	
		fi
	fi
fi
printReport

CISLevel="2"
audit="4.1 Ensure Bonjour Advertising Services Is Disabled (Automated)"
orgScore="OrgScore4_1"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.mDNSResponder > NoMulticastAdvertisements=true"

	appidentifier="com.apple.mDNSResponder"
	value="NoMulticastAdvertisements"
	prefValue=$(getPrefValue "${appidentifier}" "${value}")
	prefIsManaged=$(getPrefIsManaged "${appidentifier}" "${value}")
	comment="Bonjour advertising service: Disable"
	if [[ "${prefIsManaged}" == "true" && "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		if [[ "${prefValue}" == "true" ]]; then
			result="Passed"
		else
			result="Failed"
			comment="Bonjour advertising service: Enabled"
		fi
	fi
fi
printReport

CISLevel="1"
audit="4.2 Ensure Show Wi-Fi status in Menu Bar Is Enabled (Automated)"
orgScore="OrgScore4_2"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Profile"
	remediate="Configuration profile - payload > com.apple.controlcenter > WiFi=18"
	
	appidentifier="com.apple.controlcenter"
	value="NSStatusItem Visible WiFi"
	prefValue=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
	comment="Wi-Fi status in menu bar: Enabled"

	if [[ "${prefValue}" == "true" ]]; then
		result="Passed"
	else
		result="Failed"
		comment="Wi-Fi status in menu bar: Disabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			sudo -u ${currentUser} defaults -currentHost write com.apple.controlcenter.plist WiFi -int 18
			killall ControlCenter
			sleep 2 2>&1
			# re-check
			appidentifier="com.apple.controlcenter"
			value="NSStatusItem Visible WiFi"
			prefValue=$(getPrefValuerunAsUser "${appidentifier}" "${value}")
			if [[ "${prefValue}" == "true" ]]; then
				result="Passed After Remediation"
				comment="Wi-Fi status in menu bar: Enabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="4.4 Ensure HTTP Server Is Disabled (Automated)"
orgScore="OrgScore4_4"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl disable system/org.apache.httpd"

	httpServer=$(launchctl print-disabled system 2>&1 | grep -c '"org.apache.httpd" => false')
	if [[ "${httpServer}" != "1" ]]; then
		result="Passed"
		comment="HTTP server service: Disabled"
	else 
		result="Failed"
		comment="HTTP server service: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			launchctl disable system/org.apache.httpd
			# re-check
			httpServer=$(launchctl print-disabled system 2>&1 | grep -c '"org.apache.httpd" => false')
			if [[ "${httpServer}" != "1" ]]; then
				result="Passed After Remediation"
				comment="HTTP server service: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

CISLevel="1"
audit="4.5 Ensure NFS Server Is Disabled (Automated)"
orgScore="OrgScore4_5"
emptyVariables
# Verify organizational score
runAudit
# If organizational score is 1 or true, check status of client
if [[ "${auditResult}" == "1" ]]; then
	method="Script"
	remediate="Script > sudo launchctl disable system/com.apple.nfsd && sudo rm /etc/exports"

	httpServer=$(launchctl print-disabled system 2>&1 | grep -c '"com.apple.nfsd" => false')
	if [[ "${httpServer}" != "1" ]]; then
		result="Passed"
		comment="NFS server service: Disabled"
	else 
		result="Failed"
		comment="NFS server service: Enabled"
		# Remediation
		if [[ "${remediateResult}" == "enabled" ]]; then
			launchctl disable system/com.apple.nfsd
			rm /etc/exports
			# re-check
			httpServer=$(launchctl print-disabled system 2>&1 | grep -c '"com.apple.nfsd" => false')
			if [[ "${httpServer}" != "1" ]]; then
				result="Passed After Remediation"
				comment="NFS server service: Disabled"
			else
				result="Failed After Remediation"
			fi
		fi
	fi
fi
printReport

####################################################################################################
####################################################################################################

# Creation date CISBenchmarkReport
if [[ "${argumentHeaderFunctionName}" == "fullHeader" ]] || [[ "${reportSetting}" == "full" ]]; then
		## add creation date
		echo ";;;;;;;;;;" >> "${CISBenchmarkReport}"
		if [[ "$osVersion" = "10.15."* ]]; then
			echo "Security report - $(date) - macOS Catalina ${osVersion} (${buildVersion});;;;;;;;;;" >> "${CISBenchmarkReport}"
		elif [[ "$osVersion" = "11."* ]]; then
			echo "Security report - $(date) - macOS Big Sur ${osVersion} (${buildVersion});;;;;;;;;;" >> "${CISBenchmarkReport}"
		elif [[ "$osVersion" = "12."* ]]; then
			echo "Security report - $(date) - macOS Monterey ${osVersion} (${buildVersion});;;;;;;;;;" >> "${CISBenchmarkReport}"
		fi
        # echo "Security report - $(date);;;;;;;;;;" >> "${CISBenchmarkReport}"
	else
		echo ";;;;;;" >> "${CISBenchmarkReport}"
		if [[ "$osVersion" = "10.15."* ]]; then
			echo "Security report - $(date) - macOS Catalina ${osVersion} (${buildVersion});;;;;;" >> "${CISBenchmarkReport}"
		elif [[ "$osVersion" = "11."* ]]; then
			echo "Security report - $(date) - macOS Big Sur ${osVersion} (${buildVersion});;;;;;" >> "${CISBenchmarkReport}"
		elif [[ "$osVersion" = "12."* ]]; then
			echo "Security report - $(date) - macOS Monterey ${osVersion} (${buildVersion});;;;;;" >> "${CISBenchmarkReport}"
		fi
        # echo "Security report - $(date);;;;;;" >> "${CISBenchmarkReport}"
fi

# open "${CISBenchmarkReportPath}"
# open -a Numbers "${CISBenchmarkReport}"
# open -a "Microsoft Excel" "${CISBenchmarkReport}"

####################################################################################################
####################################################################################################
######################################## END OF THE SCRIPT #########################################
####################################################################################################
####################################################################################################
