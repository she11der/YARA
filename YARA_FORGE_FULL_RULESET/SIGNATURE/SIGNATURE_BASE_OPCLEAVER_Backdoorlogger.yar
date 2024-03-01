rule SIGNATURE_BASE_OPCLEAVER_Backdoorlogger
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "e9149baa-83c0-597f-833c-ea0241bb60e6"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L3-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c7716b21e85d7e9fb1e1503071c6cd7dc2f4713051e0b03013e3d123a0d800a6"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "BackDoorLogger"
		$s2 = "zhuAddress"

	condition:
		all of them
}
