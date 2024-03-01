rule SIGNATURE_BASE_Royalroad_Code_Pattern2 : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "135024ae-9ecf-5691-95ca-96002e500fd5"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_royalroad.yar#L42-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "e252868042e5150d99de2c2f4642f3d91d764d5a062f3a8de9ab316e299e00ac"
		score = 80
		quality = 85
		tags = "FILE"

	strings:
		$S1 = "653037396132353234666136336135356662636665" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and $S1
}
