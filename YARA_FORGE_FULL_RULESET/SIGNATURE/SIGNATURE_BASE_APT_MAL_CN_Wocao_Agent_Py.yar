rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Py
{
	meta:
		description = "Strings from Python version of Agent"
		author = "Fox-IT SRT"
		id = "ca30dd6a-b596-54ab-b4f0-50e6b1382f73"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_wocao.yar#L54-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "9b6eba750c96501aae1d86eef458d3e80de665efc7ce9d5aff842bc44363bad2"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "vpshex.decode"
		$b = "self._newsock.recv"
		$c = "Rsock.connect"
		$d = /MAX_DATALEN\s?=\s?10240/
		$e = /LISTEN_MAXCOUNT\s?=\s?80/
		$f = "ListenSock.listen(LISTEN_MAXCOUNT)"
		$g = "nextsock.send(head)"
		$h = "elif transnode"
		$i = "infobuf[4:6]"
		$key = "L\\x1bh\\x0bj\\x18\\tAZ6\\x1fV&*\\x03D}_\\x03{\\x07n\\x03w0pRBSg\\n*"

	condition:
		1 of them
}
