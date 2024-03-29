rule MALPEDIA_Win_Flawedammyy_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3bd73c1c-99e8-572f-ab1b-fa9278709331"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.flawedammyy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.flawedammyy_auto.yar#L1-L298"
		license_url = "N/A"
		logic_hash = "4dc76e66643bc2a94f8c1ec04c44669739ca4e00a00102a02a05781e927a5ab3"
		score = 75
		quality = 33
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 0000 0404 0404 0404 0401 }
		$sequence_1 = { 8bc4 83ec10 660fd600 f30f7e45ac }
		$sequence_2 = { 00b3854200e5 854200 37 864200 }
		$sequence_3 = { 8d85bcfcffff 68???????? 50 ffd3 68dff0f081 6a01 e8???????? }
		$sequence_4 = { ffd6 8d8594f3ffff 50 68???????? 68???????? }
		$sequence_5 = { 004bbf 42 0062bf 42 }
		$sequence_6 = { 0039 e342 0048e3 42 }
		$sequence_7 = { ff05???????? f7460c0c010000 7554 833cbd7cae410000 53 }
		$sequence_8 = { 8d85bcfdffff 50 ffd3 8b45fc 80384d 0f85a7000000 8078015a }
		$sequence_9 = { e8???????? 53 8d85c0fdffff 50 56 e8???????? }
		$sequence_10 = { 0018 874200 58 874200 }
		$sequence_11 = { 8b35???????? 8d85a0f6ffff 50 8d85a8f8ffff }
		$sequence_12 = { 002a e342 0039 e342 }
		$sequence_13 = { 8bf0 ff5208 85f6 0f8818feffff ff7508 8d4df0 e8???????? }
		$sequence_14 = { 0022 8a4200 828a4200bb8a42 00ff }
		$sequence_15 = { 0062bf 42 0079bf 42 }
		$sequence_16 = { ff15???????? 8b75d8 e9???????? 8d85d0feffff 68???????? 50 ff15???????? }
		$sequence_17 = { 8b46f8 834de4ff 49 c745e8ff000000 8b3c857c303400 c745ecffff0000 0faff9 }
		$sequence_18 = { 4e 48 75f7 68???????? 57 ff15???????? }
		$sequence_19 = { 8bdf 8b06 83661c00 83f807 0f87c9000000 ff248580233400 }
		$sequence_20 = { 8b46f8 8b04855c303400 c1e002 50 6a40 }
		$sequence_21 = { 8b4ef8 83f907 0f8781000000 ff248dfd243400 }
		$sequence_22 = { 7330 ff75f8 ff15???????? 81c600040000 6a42 56 }
		$sequence_23 = { eb0e 8b14957c303400 49 0fafd1 0155fc }
		$sequence_24 = { 83f937 7f2a 8d44c1d0 0fbe0a }
		$sequence_25 = { 33db 83f855 0f872affffff 0fb6805a213400 ff2485f6203400 8b8614080000 }
		$sequence_26 = { 56 8a0a 80f930 7569 }
		$sequence_27 = { 395d08 88987830ca01 0f8484010000 ff75fc 8b35???????? ffd6 f6450802 }
		$sequence_28 = { 50 e8???????? ff75ac 8b3d???????? ffd7 ff75a8 ffd7 }
		$sequence_29 = { ff248580233400 832700 e9???????? 55 e8???????? eb1a }
		$sequence_30 = { 895df0 ffd6 53 ff75dc 6813100000 ff35???????? }
		$sequence_31 = { 0f8781000000 ff248dfd243400 881f eb76 }

	condition:
		7 of them and filesize <1350656
}
