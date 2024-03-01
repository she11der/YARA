rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Powershell_Dropper
{
	meta:
		description = "Strings from the PowerShell dropper of XServer"
		author = "Fox-IT SRT"
		id = "97169ab4-d68d-5137-83de-d9cac975747e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_op_wocao.yar#L157-L168"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "640c9e52f3cf3df4e954177624e6fba4bab80a2c9442b718fe90e8577dafbbd6"
		score = 75
		quality = 85
		tags = ""

	strings:
		$encfile = "New-Object IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String($encfile)"

	condition:
		all of them
}
