rule SIGNATURE_BASE_Wmimplant
{
	meta:
		description = "Auto-generated rule - file WMImplant.ps1"
		author = "Florian Roth (Nextron Systems)"
		id = "18dadc55-e12f-5c4c-9e11-27dc2d6c8dd2"
		date = "2017-03-24"
		modified = "2023-12-05"
		reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_wmi_implant.yar#L10-L28"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6422514d25b723e7ab92c1af1301e51d9a93aa41da98791d96c4754a91b5a18e"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"

	strings:
		$x1 = "Invoke-ProcessPunisher -Creds $RemoteCredential" fullword ascii
		$x2 = "$Target -query \"SELECT * FROM Win32_NTLogEvent WHERE (logfile='security')" ascii
		$x3 = "WMImplant -Creds" fullword ascii
		$x4 = "-Download -RemoteFile C:\\passwords.txt" ascii
		$x5 = "-Command 'powershell.exe -command \"Enable-PSRemoting" fullword ascii
		$x6 = "Invoke-WMImplant" fullword ascii

	condition:
		1 of them
}
