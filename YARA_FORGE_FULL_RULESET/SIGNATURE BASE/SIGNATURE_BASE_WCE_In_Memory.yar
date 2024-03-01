import "pe"

rule SIGNATURE_BASE_WCE_In_Memory
{
	meta:
		description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
		author = "Florian Roth (Nextron Systems)"
		id = "90c90ca5-e3be-5035-b35c-c2e7faec43a5"
		date = "2016-08-28"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3265-L3279"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "74ab7772db5b1de8a4eae03370e2be3cd35004730f84d472677688109a1d6d88"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
		$s2 = "wceaux.dll" fullword ascii

	condition:
		all of them
}
