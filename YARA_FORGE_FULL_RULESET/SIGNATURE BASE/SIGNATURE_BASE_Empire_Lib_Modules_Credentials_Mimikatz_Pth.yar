rule SIGNATURE_BASE_Empire_Lib_Modules_Credentials_Mimikatz_Pth : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file pth.py"
		author = "Florian Roth (Nextron Systems)"
		id = "f954b7e8-e820-5111-ba8d-a9b9779381b0"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L118-L133"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6dee1cf931e02c5f3dc6889e879cc193325b39e18409dcdaf987b8bf7c459211"
		logic_hash = "6989c2e50ce642e0300e1293f46cd36e5141274d1e7172a8312595bb515bede2"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
		$s1 = "command = \"sekurlsa::pth /user:\"+self.options[\"user\"]['Value']" fullword ascii

	condition:
		filesize <12KB and all of them
}
