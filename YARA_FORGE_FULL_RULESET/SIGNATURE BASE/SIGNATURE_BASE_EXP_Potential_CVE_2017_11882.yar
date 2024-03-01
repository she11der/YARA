rule SIGNATURE_BASE_EXP_Potential_CVE_2017_11882 : FILE
{
	meta:
		description = "No description has been set in the source file - Signature Base"
		author = "ReversingLabs"
		id = "199710e0-5094-5940-ad29-f01383d5d8c2"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_cve_2017_11882.yar#L82-L101"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ea28010c4de86ce94537f6ab0892f6b9e28b0c775706e38bde20f48bf968d58f"
		score = 75
		quality = 60
		tags = "FILE"

	strings:
		$docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }
		$equation1 = "Equation Native" wide ascii
		$equation2 = "Microsoft Equation 3.0" wide ascii
		$mshta = "mshta"
		$http = "http://"
		$https = "https://"
		$cmd = "cmd" fullword
		$pwsh = "powershell"
		$exe = ".exe"
		$address = { 12 0C 43 00 }

	condition:
		uint16(0)==0xcfd0 and $docfilemagic at 0 and any of ($mshta,$http,$https,$cmd,$pwsh,$exe) and any of ($equation1,$equation2) and $address
}
