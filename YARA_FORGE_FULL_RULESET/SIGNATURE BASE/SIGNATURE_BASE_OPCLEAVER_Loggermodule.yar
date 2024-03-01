rule SIGNATURE_BASE_OPCLEAVER_Loggermodule
{
	meta:
		description = "Keylogger used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "949e7ff4-2102-5c89-83c9-f7ba64745661"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_cleaver.yar#L36-L50"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dd937bc3fc7054874a3c61bbef859dd8a8ec37872a30be6d3e1776957f98db80"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "%s-%02d%02d%02d%02d%02d.r"
		$s2 = "C:\\Users\\%s\\AppData\\Cookies\\"

	condition:
		all of them
}
