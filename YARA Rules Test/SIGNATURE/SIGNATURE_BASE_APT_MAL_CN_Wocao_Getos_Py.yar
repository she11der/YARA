rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Getos_Py
{
	meta:
		description = "Python getos utility"
		author = "Fox-IT SRT"
		id = "4a731dde-87e4-566a-b559-d23e0bef5841"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L234-L295"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "2535c01b703c0fcba43e771832db8cd969e4a4b112ef28e4ddfeac6491ba604c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$smb_1 = {
            00 00 00 85 ff 53 4d 42 72 00 00 00 00 18 53 c8
            00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff fe
            00 00 ff b4 00 62 00 02 50 43 20 4e 45 54 57 4f
            52 4b 20 50 52 4f 47 52 41 4d 20 31 2e 30 00 02
            4c 41 4e 4d 41 4e 31 2e 30 00 02 57 69 6e 64 6f
            77 73 20 66 6f 72 20 57 6f 72 6b 67 72 6f 75 70
            73 20 33 2e 31 61 00 02 4c 4d 31 2e 32 58 30 30
            32 00 02 4c 41 4e 4d 41 4e 32 2e 31 00 02 4e 54
            20 4c 4d 20 30 2e 31 32 00
}