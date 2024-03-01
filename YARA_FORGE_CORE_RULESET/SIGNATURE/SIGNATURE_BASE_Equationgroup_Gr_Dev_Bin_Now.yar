rule SIGNATURE_BASE_Equationgroup_Gr_Dev_Bin_Now : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_eqgrp_apr17.yar#L1258-L1272"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1d7f009c5593ac1b1517024b828b016d705b63f6812a49d909f35c34b936e6d7"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "f5ed8312fc6e624b04e1e2d6614f3c651c9e9902ff41f4d069c32caca0869fa4"

	strings:
		$x1 = "HTTP_REFERER=\"https://127.0.0.1:6655/cgi/redmin?op=cron&action=once\"" fullword ascii
		$x2 = "exec /usr/share/redmin/cgi/redmin" fullword ascii

	condition:
		( filesize <1KB and 1 of them )
}
