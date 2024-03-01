import "pe"

rule SIGNATURE_BASE_HKTL_Portscanner_Simple_Jan14
{
	meta:
		description = "Auto-generated rule on file PortScanner.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "3e8960ce-0428-51e1-b992-4fa09fee8520"
		date = "2023-12-05"
		modified = "2023-12-05"
		old_rule_name = "PortScanner"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L171-L183"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "b381b9212282c0c650cb4b0323436c63"
		logic_hash = "c69269b227d46b5b970cfc094b3154b0a533b439b8ed492a2059025bc96d17a0"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Scan Ports Every"
		$s3 = "Scan All Possible Ports!"

	condition:
		all of them
}
