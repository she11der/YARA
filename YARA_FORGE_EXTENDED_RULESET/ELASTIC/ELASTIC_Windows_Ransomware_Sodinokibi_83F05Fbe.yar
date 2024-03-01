rule ELASTIC_Windows_Ransomware_Sodinokibi_83F05Fbe : beta FILE MEMORY
{
	meta:
		description = "Identifies SODINOKIBI/REvil ransomware"
		author = "Elastic Security"
		id = "83f05fbe-65d1-423f-98df-21692167a1d6"
		date = "2020-06-18"
		modified = "2021-08-23"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.revil"
		source_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/yara/rules/Windows_Ransomware_Sodinokibi.yar#L1-L34"
		license_url = "https://github.com/elastic/protections-artifacts//blob/84213d9b40fee553ea3065cb4bb057c7c1685b59/LICENSE.txt"
		logic_hash = "c88fc2690deae3700e605b2affb5ecac3d1ffc92435f33209f31897d28715b8c"
		score = 75
		quality = 73
		tags = "FILE, MEMORY"
		fingerprint = "8c32ca099c9117e394379c0cc4771a15e5e4cfb1a98210c288e743a6d9cc9967"
		threat_name = "Windows.Ransomware.Sodinokibi"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$d1 = { 03 C0 01 47 30 11 4F 34 01 57 30 8B 57 78 8B C2 11 77 34 8B 77 7C 8B CE 0F A4 C1 04 C1 E0 04 01 47 28 8B C2 11 4F 2C 8B CE 0F A4 C1 01 03 C0 01 47 28 11 4F 2C 01 57 28 8B 57 70 8B C2 11 77 2C 8B 77 74 8B CE 0F A4 C1 04 C1 E0 04 01 47 20 8B C2 11 4F 24 8B CE 0F A4 C1 01 03 C0 01 47 20 11 4F 24 01 57 20 8B 57 68 8B C2 11 77 24 8B 77 6C 8B CE 0F A4 C1 04 C1 E0 04 01 47 18 8B C2 11 4F 1C 8B CE 0F A4 C1 01 03 C0 01 47 18 11 4F 1C 01 57 18 8B 57 60 8B C2 11 77 1C 8B 77 64 }
		$d2 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B }
		$d3 = { F7 6F 38 03 C8 8B 43 48 13 F2 F7 6F 20 03 C8 8B 43 38 13 F2 F7 6F 30 03 C8 8B 43 40 13 F2 F7 6F 28 03 C8 8B 43 28 13 F2 F7 6F 40 03 C8 8B 45 08 13 F2 89 48 68 89 70 6C 8B 43 38 F7 6F 38 8B C8 8B F2 8B 43 28 F7 6F 48 03 C8 13 F2 8B 43 48 F7 6F 28 03 C8 8B 43 30 13 F2 F7 6F 40 0F A4 CE 01 03 C9 03 C8 8B 43 40 13 F2 F7 6F 30 03 C8 8B 45 08 13 F2 89 48 70 89 70 74 8B 43 38 F7 6F 40 8B C8 }
		$d4 = { 33 C0 8B 5A 68 8B 52 6C 0F A4 FE 08 C1 E9 18 0B C6 C1 E7 08 8B 75 08 0B CF 89 4E 68 8B CA 89 46 6C 33 C0 8B 7E 60 8B 76 64 0F A4 DA 19 C1 E9 07 0B C2 C1 E3 19 8B 55 08 0B CB 89 4A 60 8B CF 89 42 64 33 C0 8B 5A 10 8B 52 14 0F AC F7 15 C1 E1 0B C1 EE 15 0B C7 0B CE 8B 75 }
		$d5 = { C1 01 C1 EE 1F 0B D1 03 C0 0B F0 8B C2 33 43 24 8B CE 33 4B 20 33 4D E4 33 45 E0 89 4B 20 8B CB 8B 5D E0 89 41 24 8B CE 33 4D E4 8B C2 31 4F 48 33 C3 8B CF 31 41 4C 8B C7 8B CE 33 48 70 8B C2 33 47 74 33 4D E4 33 C3 89 4F 70 8B CF 89 41 74 8B }
		$d6 = { 8B 43 40 F7 6F 08 03 C8 8B 03 13 F2 F7 6F 48 03 C8 8B 43 48 13 F2 F7 2F 03 C8 8B 43 08 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 18 03 C8 8B 43 18 13 F2 F7 6F 30 03 C8 8B 43 38 13 F2 F7 6F 10 03 C8 8B 43 10 13 F2 F7 6F 38 03 C8 8B 43 28 13 F2 }
		$d7 = { 8B CE 33 4D F8 8B C2 33 C3 31 4F 18 8B CF 31 41 1C 8B C7 8B CE 33 48 40 8B C2 33 4D F8 33 47 44 89 4F 40 33 C3 8B CF 89 41 44 8B C7 8B CE 33 48 68 8B C2 33 47 6C 33 4D F8 33 C3 89 4F 68 8B CF 89 41 6C 8B CE 8B }
		$d8 = { 36 7D 49 30 85 35 C2 C3 68 60 4B 4B 7A BE 83 53 AB E6 8E 42 F9 C6 62 A5 D0 6A AD C6 F1 7D F6 1D 79 CD 20 FC E7 3E E1 B8 1A 43 38 12 C1 56 28 1A 04 C9 22 55 E0 D7 08 BB 9F 0B 1F 1C B9 13 06 35 }
		$d9 = { C2 C1 EE 03 8B 55 08 0B CE 89 4A 4C 8B CF 89 42 48 33 C0 8B 72 30 8B 52 34 C1 E9 0C 0F A4 DF 14 0B C7 C1 E3 14 8B 7D 08 0B CB 89 4F 30 8B CE 89 47 34 33 C0 C1 E1 0C 0F AC D6 14 0B C6 C1 EA 14 89 47 08 0B CA }
		$d10 = { 8B F2 8B 43 38 F7 6F 28 03 C8 8B 43 18 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 38 03 C8 8B 43 40 13 F2 F7 6F 20 0F A4 CE 01 03 C9 03 C8 8B 43 20 13 F2 F7 6F 40 03 C8 8B 43 30 13 F2 F7 6F 30 03 C8 }
		$d11 = { 33 45 FC 31 4B 28 8B CB 31 41 2C 8B CE 8B C3 33 48 50 8B C2 33 43 54 33 CF 33 45 FC 89 4B 50 8B CB 89 41 54 8B CE 8B C3 33 48 78 8B C2 33 43 7C 33 CF 33 45 FC 89 4B 78 8B CB 89 41 7C 33 B1 A0 }
		$d12 = { 52 24 0F A4 FE 0E C1 E9 12 0B C6 C1 E7 0E 8B 75 08 0B CF 89 4E 20 8B CA 89 46 24 33 C0 8B 7E 78 8B 76 7C 0F A4 DA 1B C1 E9 05 0B C2 C1 E3 1B 8B 55 08 0B CB 89 4A 78 8B CF 89 42 7C 33 C0 8B 9A }
		$d13 = { F2 8B 43 38 F7 6F 20 03 C8 8B 43 40 13 F2 F7 6F 18 03 C8 8B 43 10 13 F2 F7 6F 48 03 C8 8B 43 28 13 F2 F7 6F 30 03 C8 8B 43 20 13 F2 F7 6F 38 03 C8 8B 43 30 13 F2 F7 6F 28 03 C8 8B 43 48 13 F2 }
		$d14 = { 8B 47 30 13 F2 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 74 03 C9 89 4B 70 8B 47 30 F7 6F 48 8B C8 8B F2 8B 47 38 F7 6F 40 03 C8 13 F2 0F A4 CE 01 89 73 7C 03 C9 89 4B 78 8B 47 38 F7 6F 48 8B C8 }

	condition:
		all of them
}
