rule SIGNATURE_BASE_Chinachopper_Temp : FILE
{
	meta:
		description = "Chinese Hacktool Set - file temp.asp"
		author = "Florian Roth (Nextron Systems)"
		id = "f163787f-fcc9-568a-a12d-4057cb4f0d29"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L309-L325"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b0561ea52331c794977d69704345717b4eb0a2a7"
		logic_hash = "3669dfa10867970456f6638035a87d448e2b728387fbd07b59ffd981a1ab6200"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "o.run \"ff\",Server,Response,Request,Application,Session,Error" fullword ascii
		$s1 = "Set o = Server.CreateObject(\"ScriptControl\")" fullword ascii
		$s2 = "o.language = \"vbscript\"" fullword ascii
		$s3 = "o.addcode(Request(\"SC\"))" fullword ascii

	condition:
		filesize <1KB and all of them
}
