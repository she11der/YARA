import "pe"

rule SIGNATURE_BASE_IMPLANT_5_V3
{
	meta:
		description = "XTunnel Implant by APT28"
		author = "US CERT"
		id = "0763e314-85d0-5c16-b766-36298176e0ff"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_grizzlybear_uscert.yar#L1194-L1207"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "aec1314858732d30b62a033e85eea50b3375e4f5b0e1818a941979d5be672297"
		score = 85
		quality = 85
		tags = ""

	strings:
		$BYTES1 = { 0F AF C0 6? C0 07 00 00 00 2D 01 00 00 00 0F AF ?? 39 ?8 }
		$BYTES2 = { 0F AF C0 6? C0 07 48 0F AF ?? 39 ?8 }

	condition:
		any of them
}
