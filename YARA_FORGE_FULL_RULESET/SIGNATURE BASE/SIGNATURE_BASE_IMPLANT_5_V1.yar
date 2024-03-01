import "pe"

rule SIGNATURE_BASE_IMPLANT_5_V1
{
	meta:
		description = "XTunnel Implant by APT28"
		author = "US CERT"
		id = "dee08753-3465-5bf2-acd5-aa6cc80aba3c"
		date = "2017-02-10"
		modified = "2023-12-05"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_grizzlybear_uscert.yar#L1034-L1051"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "d94192d408036bf02052dc5145b78fea61323810b2abdbba64c65e1f6387ea42"
		score = 85
		quality = 85
		tags = ""

	strings:
		$hexstr = {2D 00 53 00 69 00 00 00 2D 00 53 00 70 00 00 00 2D 00 55 00
         70 00 00 00 2D 00 50 00 69 00 00 00 2D 00 50 00 70 00 00 00}
		$UDPMSG1 = "error 2005 recv from server UDP - %d\x0a"
		$TPSMSG1 = "error 2004 send to TPS - %d\x0a"
		$TPSMSG2 = "error 2003 recv from TPS - %d\x0a"
		$UDPMSG2 = "error 2002 send to server UDP - %d\x0a"

	condition:
		any of them
}
