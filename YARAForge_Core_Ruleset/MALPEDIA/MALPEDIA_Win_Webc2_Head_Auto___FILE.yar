rule MALPEDIA_Win_Webc2_Head_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "fbb157f3-5522-59eb-8966-994ac95b42ec"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.webc2_head"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.webc2_head_auto.yar#L1-L115"
		license_url = "N/A"
		logic_hash = "3accb9e007709b9cb8a99022cd642781f2c16d496b60a9e07fc0420c29da6736"
		score = 75
		quality = 75
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
		$sequence_0 = { 8a8c0cc0000000 eb02 b13d c1e810 83e03f 0fbec9 }
		$sequence_1 = { 68???????? 55 55 896c2434 ffd7 }
		$sequence_2 = { 8d942444080000 03f0 51 50 52 55 ff15???????? }
		$sequence_3 = { e8???????? 83c40c 85c0 0f8554020000 b900050000 }
		$sequence_4 = { 33db 89442418 52 c6450000 }
		$sequence_5 = { 7513 8dbc2444040000 83c9ff f2ae f7d1 49 894c241c }
		$sequence_6 = { 89442410 c1e002 89442418 8b4c2424 }
		$sequence_7 = { eb02 b03d 884303 8b442410 }
		$sequence_8 = { 83c410 c3 5f c6450000 5e }
		$sequence_9 = { 2500ff0000 45 3d003d0000 7435 }

	condition:
		7 of them and filesize <106496
}