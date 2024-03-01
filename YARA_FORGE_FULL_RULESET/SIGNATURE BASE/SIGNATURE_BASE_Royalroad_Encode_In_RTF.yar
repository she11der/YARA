rule SIGNATURE_BASE_Royalroad_Encode_In_RTF : FILE
{
	meta:
		description = "Detects RoyalRoad weaponized RTF documents"
		author = "nao_sec"
		id = "66614152-8f9b-5e62-b6bd-ba0286e66d4d"
		date = "2020-01-15"
		modified = "2023-12-05"
		reference = "https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_8_koike-nakajima_jp.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_royalroad.yar#L168-L189"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "00a703a0d7b3a74ec9bfc8ad0e570ee04b3cb6b7f2c062cc2886b41f6fbea49d"
		score = 60
		quality = 85
		tags = "FILE"

	strings:
		$enc_hex_1 = "B0747746"
		$enc_hex_2 = "B2A66DFF"
		$enc_hex_3 = "F2A32072"
		$enc_hex_4 = "B2A46EFF"
		$enc_hex_1l = "b0747746"
		$enc_hex_2l = "b2a66Dff"
		$enc_hex_3l = "f2a32072"
		$enc_hex_4l = "b2a46eff"
		$RTF = "{\\rt"

	condition:
		$RTF at 0 and 1 of ($enc_hex*)
}
