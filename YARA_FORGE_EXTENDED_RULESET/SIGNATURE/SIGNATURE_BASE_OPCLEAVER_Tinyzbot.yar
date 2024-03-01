rule SIGNATURE_BASE_OPCLEAVER_Tinyzbot
{
	meta:
		description = "Tiny Bot used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "4fad21a6-a900-5afb-876d-99a6d93e0c2c"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L117-L138"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fdc41fbec71602e13105a03a4f44319a139018bda00e87e8f4d9b5e2f6269c14"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "NetScp" wide
		$s2 = "TinyZBot.Properties.Resources.resources"
		$s3 = "Aoao WaterMark"
		$s4 = "Run_a_exe"
		$s5 = "netscp.exe"
		$s6 = "get_MainModule_WebReference_DefaultWS"
		$s7 = "remove_CheckFileMD5Completed"
		$s8 = "http://tempuri.org/"
		$s9 = "Zhoupin_Cleaver"

	condition:
		(($s1 and $s2) or ($s3 and $s4 and $s5) or ($s6 and $s7 and $s8) or $s9)
}
