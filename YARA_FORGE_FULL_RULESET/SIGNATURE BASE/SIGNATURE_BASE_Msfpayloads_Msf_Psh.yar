rule SIGNATURE_BASE_Msfpayloads_Msf_Psh
{
	meta:
		description = "Metasploit Payloads - file msf-psh.vba"
		author = "Florian Roth (Nextron Systems)"
		id = "5b760f03-b0f8-5871-bd34-e7e44443530c"
		date = "2017-02-09"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_metasploit_payloads.yar#L42-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2e6015e8c91ccd8647e78220d10c2d704867369d962b734bb4522a1213be2f2d"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"

	strings:
		$s1 = "powershell.exe -nop -w hidden -e" ascii
		$s2 = "Call Shell(" ascii
		$s3 = "Sub Workbook_Open()" fullword ascii

	condition:
		all of them
}
