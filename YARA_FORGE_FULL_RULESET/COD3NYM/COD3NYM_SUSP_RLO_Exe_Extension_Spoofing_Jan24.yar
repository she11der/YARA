rule COD3NYM_SUSP_RLO_Exe_Extension_Spoofing_Jan24
{
	meta:
		description = "Detects Right-To-Left (RLO) Unicode (U+202E) extension spoofing for .exe files"
		author = "Jonathan Peters"
		id = "60c1a8db-6bfc-547b-98d9-21c198a703f0"
		date = "2024-01-14"
		modified = "2024-02-19"
		reference = "https://unprotect.it/technique/right-to-left-override-rlo-extension-spoofing/"
		source_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/yara/other/susp_rlo_exe_extension_spoofing.yar#L2-L58"
		license_url = "https://github.com/cod3nym/detection-rules//blob/ad485bff0ce30afb56e367b7f2b76fea81e78fc9/LICENSE.md"
		hash = "cae0ab10f7c1afd7941aff767a9b59901270e3de4d44167e932dae0991515487"
		logic_hash = "6126f36b3cd695b4002c29c9163faa6ec295699863d8db7fe17afc407f5a5736"
		score = 70
		quality = 55
		tags = ""

	strings:
		$ = { E2 80 AE 76 73 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 78 73 6C 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 78 63 6F 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 70 69 7A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 67 6E 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 67 65 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 67 70 6A ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6E 6C 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 74 78 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 66 64 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 78 74 70 70 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 74 64 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 63 74 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 66 69 67 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 70 6d 62 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 66 66 69 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 67 76 73 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 34 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 69 76 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 76 6f 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 76 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 76 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 76 6b 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 33 70 6d ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 76 61 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 63 61 61 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 63 61 6c 66 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 67 67 6f ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 61 6d 77 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 72 61 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 7a 37 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 7a 67 72 61 74 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6f 73 69 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6c 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6c 6d 65 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6d 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 66 74 72 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6d 68 63 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 61 74 68 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6b 6e 6c ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 73 6c 78 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }
		$ = { E2 80 AE 6d 63 6f 64 ( 2E 2E | 2E ) ( 65 78 65 | 73 63 72 ) }

	condition:
		1 of them
}
