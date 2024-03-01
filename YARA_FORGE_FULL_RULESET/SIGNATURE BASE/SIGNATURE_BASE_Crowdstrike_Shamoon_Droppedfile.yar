rule SIGNATURE_BASE_Crowdstrike_Shamoon_Droppedfile
{
	meta:
		description = "Rule to detect Shamoon malware http://goo.gl/QTxohN"
		author = "Florian Roth"
		id = "b350f1b1-db73-574b-957b-34e5a84f68b0"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "http://www.rsaconference.com/writable/presentations/file_upload/exp-w01-hacking-exposed-day-of-destruction.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_shamoon.yar#L1-L13"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ed550832b217f7edceea2edf7c4453925ed1759d97db7728f7face6ff10ee361"
		score = 75
		quality = 85
		tags = ""

	strings:
		$testn123 = "test123" wide
		$testn456 = "test456" wide
		$testn789 = "test789" wide
		$testdomain = "testdomain.com" wide
		$pingcmd = "ping -n 30 127.0.0.1 >nul" wide

	condition:
		( any of ($testn*) or $pingcmd) and $testdomain
}
