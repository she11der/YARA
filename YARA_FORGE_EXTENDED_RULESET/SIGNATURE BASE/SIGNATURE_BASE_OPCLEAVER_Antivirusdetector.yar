rule SIGNATURE_BASE_OPCLEAVER_Antivirusdetector
{
	meta:
		description = "Hack tool used by attackers in Operation Cleaver"
		author = "Cylance Inc."
		id = "25ab4eaf-eae7-5a55-bed4-42f621d5f06c"
		date = "2014-12-02"
		modified = "2023-12-05"
		reference = "http://cylance.com/assets/Cleaver/Cylance_Operation_Cleaver_Report.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_cleaver.yar#L156-L171"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9a8c2bbd27efab4c5579ea143abbd2f71c477dfd0ddbfb1741359e4d34140d9b"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "getShadyProcess"
		$s2 = "getSystemAntiviruses"
		$s3 = "AntiVirusDetector"

	condition:
		all of them
}
