rule SIGNATURE_BASE_Msfpayloads_Msf_Exe_2
{
	meta:
		description = "Metasploit Payloads - file msf-exe.aspx"
		author = "Florian Roth (Nextron Systems)"
		id = "a55a33e1-8f04-5417-af0c-b7e2da36fb46"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L123-L139"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "bd82f496ade1a62e0aee8c8c90cee84377cb90adf11c87652082e74c8c85e568"
		score = 75
		quality = 83
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "3a2f7a654c1100e64d8d3b4cd39165fba3b101bbcce6dd0f70dae863da338401"

	strings:
		$x1 = "= new System.Diagnostics.Process();" fullword ascii
		$x2 = ".StartInfo.UseShellExecute = true;" fullword ascii
		$x3 = ", \"svchost.exe\");" ascii
		$s4 = " = Path.GetTempPath();" ascii

	condition:
		all of them
}
