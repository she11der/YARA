rule BINARYALERT_Hacktool_Macos_Juuso_Keychaindump
{
	meta:
		description = "For reading OS X keychain passwords as root."
		author = "@mimeframe"
		id = "10ee6c24-db35-5178-9a40-92f5231948aa"
		date = "2017-09-12"
		modified = "2017-09-12"
		reference = "https://github.com/juuso/keychaindump"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/hacktool/macos/hacktool_macos_juuso_keychaindump.yara#L1-L16"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "dd2fb6249fe4b7381e734ea3a308158159f7e79b39ba5c970241dcd66436d669"
		score = 75
		quality = 80
		tags = ""

	strings:
		$a1 = "[-] Too many candidate keys to fit in memory" wide ascii
		$a2 = "[-] Could not allocate memory for key search" wide ascii
		$a3 = "[-] Too many credentials to fit in memory" wide ascii
		$a4 = "[-] The target file is not a keychain file" wide ascii
		$a5 = "[-] Could not find the securityd process" wide ascii
		$a6 = "[-] No root privileges, please run with sudo" wide ascii

	condition:
		4 of ($a*)
}
