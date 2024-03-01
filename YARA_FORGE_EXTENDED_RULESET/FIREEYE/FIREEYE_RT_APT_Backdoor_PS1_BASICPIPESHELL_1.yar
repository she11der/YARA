import "pe"

rule FIREEYE_RT_APT_Backdoor_PS1_BASICPIPESHELL_1
{
	meta:
		description = "No description has been set in the source file - FireEye-RT"
		author = "FireEye"
		id = "8f85d6cc-fd1e-5bf3-8052-440cbeda0ac9"
		date = "2020-12-18"
		modified = "2020-12-18"
		reference = "https://github.com/mandiant/red_team_tool_countermeasures/"
		source_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/rules/BASICPIPESHELL/production/yara/APT_Backdoor_PS1_BASICPIPESHELL_1.yar#L5-L18"
		license_url = "https://github.com/mandiant/red_team_tool_countermeasures//blob/abcba6e9291a04ec1093ce3a4b0b258c1eb891ef/LICENSE.txt"
		logic_hash = "7a9f0002055ffe826562cab3d02d8babd14c5fcd6d0b528a2988e2649034279d"
		score = 75
		quality = 63
		tags = ""

	strings:
		$s1 = "function Invoke-Client()" ascii nocase wide
		$s2 = "function Invoke-Server" ascii nocase wide
		$s3 = "Read-Host 'Enter Command:'" ascii nocase wide
		$s4 = "new-object System.IO.Pipes.NamedPipeClientStream(" ascii nocase wide
		$s5 = "new-object System.IO.Pipes.NamedPipeServerStream(" ascii nocase wide
		$s6 = " = iex $" ascii nocase wide

	condition:
		all of them
}
