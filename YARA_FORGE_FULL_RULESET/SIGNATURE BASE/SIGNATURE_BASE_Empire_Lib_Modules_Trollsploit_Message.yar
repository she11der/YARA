rule SIGNATURE_BASE_Empire_Lib_Modules_Trollsploit_Message : FILE
{
	meta:
		description = "Empire - a pure PowerShell post-exploitation agent - file message.py"
		author = "Florian Roth (Nextron Systems)"
		id = "cb0eee5a-c236-512e-8256-7411a7fb1fd5"
		date = "2015-08-06"
		modified = "2023-12-05"
		reference = "https://github.com/PowerShellEmpire/Empire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_powershell_empire.yar#L28-L45"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "71f2258177eb16eafabb110a9333faab30edacf67cb019d5eab3c12d095655d5"
		logic_hash = "70b7d91395ae30131c1448511425abf32ddedf04632266454aa008330ff28222"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "script += \" -\" + str(option) + \" \\\"\" + str(values['Value'].strip(\"\\\"\")) + \"\\\"\"" fullword ascii
		$s2 = "if option.lower() != \"agent\" and option.lower() != \"computername\":" fullword ascii
		$s3 = "[String] $Title = 'ERROR - 0xA801B720'" fullword ascii
		$s4 = "'Value'         :   'Lost contact with the Domain Controller.'" fullword ascii

	condition:
		filesize <10KB and 3 of them
}
