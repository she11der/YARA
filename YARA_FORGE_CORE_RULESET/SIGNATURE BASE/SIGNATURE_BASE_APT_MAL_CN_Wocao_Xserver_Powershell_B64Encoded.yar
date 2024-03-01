rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Powershell_B64Encoded
{
	meta:
		description = "Piece of Base64 encoded data from the XServer PowerShell dropper"
		author = "Fox-IT SRT"
		id = "01e38cfb-b245-5398-b037-6d1d2fb726ee"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L143-L155"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "77315f0fc8387fa87892fc8fcea1f6e8a95560049aaa9a87519859020d0a7a3e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$header_47000 = "5T39c9u2kr/nr2A0Ny2VKIzkfLRJntuJHafPN/nwWG777rUZDy3BNq8UqSEpx26b"
		$header_25667 = "5T1rc9u2st/zKxjNmZZKFEZyErdJ6nZsx+nxnTjxWGp77mkzHlqCbd5SpIak/Gjr"

	condition:
		any of them
}
