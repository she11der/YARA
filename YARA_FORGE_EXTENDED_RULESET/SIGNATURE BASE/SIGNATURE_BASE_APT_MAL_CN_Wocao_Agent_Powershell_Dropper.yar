rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Agent_Powershell_Dropper
{
	meta:
		description = "Strings from PowerShell dropper of CSharp version of Agent"
		author = "Fox-IT SRT"
		id = "833ce607-56a9-5580-bbd1-e72392945fec"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_op_wocao.yar#L24-L38"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "19f56e69685ae8c13b9dd884f8322915835c16e2c6313f01f9fa447218419108"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "function format([string]$source)"
		$b = "foreach($c in $bb){$tt = $tt + [char]($c -bxor"
		$c = "[agent]::Main($args);"

	condition:
		1 of them
}
