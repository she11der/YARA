rule MALPEDIA_Win_Jripbot_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "7b1d247f-7cbb-5615-a25c-7a029e86230e"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.jripbot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.jripbot_auto.yar#L1-L133"
		license_url = "N/A"
		logic_hash = "e485f4c42ec7ab7e0d2df3f1cd3bb910f7710773a4391061675b3c77a4acf337"
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
		$sequence_0 = { 48 3b442418 0f822bffffff 8b8c24fc010000 5f 5e 5b }
		$sequence_1 = { c1e807 8807 02d2 885701 66c7060100 33c9 837b0401 }
		$sequence_2 = { 8b5d08 c1eb08 23d8 0fb69b38834200 c1e608 33f3 8b5d0c }
		$sequence_3 = { 8d742414 e8???????? 59 59 eb06 895c240c 33c0 }
		$sequence_4 = { 33c0 8b8eb8000000 3bc7 0f95c0 6a02 884105 33db }
		$sequence_5 = { 51 50 56 56 ff750c ff75fc ffd7 }
		$sequence_6 = { 50 e8???????? 8b1d???????? 83c40c 8d442438 50 ff15???????? }
		$sequence_7 = { 8b4004 894604 33c0 8b8c242c010000 5f 5e 5b }
		$sequence_8 = { eb04 8b442430 8b4c241c 2b4c2418 ff742418 8b5c2438 }
		$sequence_9 = { 7443 3bf8 743f 8b4368 397008 7537 8b4df4 }

	condition:
		7 of them and filesize <507904
}