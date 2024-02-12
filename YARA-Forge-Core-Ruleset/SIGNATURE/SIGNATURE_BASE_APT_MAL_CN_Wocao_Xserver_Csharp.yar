rule SIGNATURE_BASE_APT_MAL_CN_Wocao_Xserver_Csharp
{
	meta:
		description = "Strings from the CSharp version of XServer"
		author = "Fox-IT SRT"
		id = "48f4c88d-fb56-54ca-84e2-38f88804a50f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_op_wocao.yar#L123-L141"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1201ee45df78cf3aec4b4bbb59cb7e4a70af6928895bb7c968ef02075a963405"
		score = 75
		quality = 85
		tags = ""

	strings:
		$a = "static void ServerX(int ListenPort)" ascii wide
		$b = "public class xserver" ascii wide
		$c = "[xserver]::Main($args);" ascii wide
		$d = "add rule name=powershell dir=in localport=47000 action=allow" ascii wide
		$e = "string TempFile = file_path + \".CT\";" ascii wide
		$f = "Port = 256 * RecvBuf[AddrLen + 5] + RecvBuf[AddrLen + 6];"
		$g = "CliSock.Send(new byte[] { 0x05, 0x00 });"

	condition:
		1 of them
}