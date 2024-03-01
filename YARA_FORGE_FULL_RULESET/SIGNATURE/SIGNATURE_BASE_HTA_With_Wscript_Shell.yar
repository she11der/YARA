rule SIGNATURE_BASE_HTA_With_Wscript_Shell
{
	meta:
		description = "Detects WScript Shell in HTA"
		author = "Florian Roth (Nextron Systems)"
		id = "2faf74b1-c19c-53f0-ad08-be9caf5640bc"
		date = "2017-06-21"
		modified = "2023-12-05"
		reference = "https://twitter.com/msftmmpc/status/877396932758560768"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_hta_anomalies.yar#L11-L26"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7ce2728fbd3023a6b96291cdb63f30dc9b71e5fc506f8b00ad97e3062b103478"
		score = 80
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"

	strings:
		$s1 = "<hta:application windowstate=\"minimize\"/>"
		$s2 = "<script>var b=new ActiveXObject(\"WScript.Shell\");" ascii

	condition:
		all of them
}
