rule SIGNATURE_BASE_Empire_Invoke_Wmi : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
		author = "Florian Roth (Nextron Systems)"
		id = "1e1d1e71-6ea9-500a-b8b8-c48a64bc2b54"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_powershell_empire.yar#L172-L188"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a914cb227f652734a91d3d39745ceeacaef7a8b5e89c1beedfd6d5f9b4615a1d"
		logic_hash = "7179a22eec8eb9e59bf590e671e6849d5b960c58eb8fa591bc3b340d64f1d076"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
		$s2 = "script += \";'Invoke-Wmi executed on \" +computerNames +\"'\"" fullword ascii
		$s3 = "script = \"$PSPassword = \\\"\"+password+\"\\\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Man" ascii

	condition:
		filesize <20KB and 2 of them
}
