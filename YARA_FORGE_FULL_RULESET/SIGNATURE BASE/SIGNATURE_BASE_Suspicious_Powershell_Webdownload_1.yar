rule SIGNATURE_BASE_Suspicious_Powershell_Webdownload_1 : HIGHVOL FILE
{
	meta:
		description = "Detects suspicious PowerShell code that downloads from web sites"
		author = "Florian Roth (Nextron Systems)"
		id = "a763fb82-c840-531b-b631-f282bf035020"
		date = "2017-02-22"
		modified = "2022-07-27"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_susp.yar#L52-L81"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "4e07ea202ca4e96c7dc4578045aa065aa7fa19b2b90cfe47359aafbb31f3c68a"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		nodeepdive = 1

	strings:
		$s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
		$s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
		$s3 = "system.net.webclient).downloadfile('http" ascii nocase
		$s4 = "system.net.webclient).downloadfile(\"http" ascii nocase
		$s5 = "GetString([Convert]::FromBase64String(" ascii nocase
		$fp1 = "NuGet.exe" ascii fullword
		$fp2 = "chocolatey.org" ascii
		$fp3 = " GET /"
		$fp4 = " POST /"
		$fp5 = ".DownloadFile('https://aka.ms/installazurecliwindows', 'AzureCLI.msi')" ascii
		$fp6 = " 404 "
		$fp7 = "# RemoteSSHConfigurationScript" ascii
		$fp8 = "<helpItems" ascii fullword
		$fp9 = "DownloadFile(\"https://codecov.io/bash" ascii

	condition:
		1 of ($s*) and not 1 of ($fp*)
}
