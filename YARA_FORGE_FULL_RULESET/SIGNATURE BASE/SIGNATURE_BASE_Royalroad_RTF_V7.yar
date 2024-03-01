rule SIGNATURE_BASE_Royalroad_RTF_V7 : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "9d2af980-a851-533a-b25d-ee52277e319c"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_royalroad.yar#L150-L166"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "da043123cf72e19295634720196d78bef3af89f44cba795dbbcee4c0f5c8159a"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$v7_1 = "{\\object\\objocx{\\objdata" ascii
		$v7_2 = "ods0000" ascii
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and all of ($v7*)
}
