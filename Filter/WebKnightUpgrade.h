#pragma once

#include "StringHelper.h"
#include "WebKnightSettings.h"

class CWebKnightUpgrade : protected CStringHelper
{
protected:
	static void UpgradeJavaScriptKeywords3_2(CStringList& list);
	static void UpgradeJavaScriptKeywords4_3(CStringList& list);
	static void UpgradeJavaScriptKeywords4_4(CStringList& list);
	static void UpgradeJavaScriptKeywords4_5(CStringList& list);

	//InternalUpgrade upgrades older settings files (applying all deltas with signatures)
	static void InternalUpgrade3_1(CWebKnightSettings& Settings);
	static void InternalUpgrade3_2(CWebKnightSettings& Settings);
	static void InternalUpgrade3_3(CWebKnightSettings& Settings);

	static void InternalUpgrade4_1(CWebKnightSettings& Settings);
	static void InternalUpgrade4_2(CWebKnightSettings& Settings);
	static void InternalUpgrade4_3(CWebKnightSettings& Settings);
	static void InternalUpgrade4_4(CWebKnightSettings& Settings);
	static void InternalUpgrade4_5(CWebKnightSettings& Settings);
	static void InternalUpgrade4_6(CWebKnightSettings& Settings);
	static void InternalUpgrade4_7(CWebKnightSettings& Settings);

public:
	CWebKnightUpgrade(void);
	virtual ~CWebKnightUpgrade(void);

	static void Upgrade(CWebKnightSettings& Settings);

	static void Upgrade4_3(CWebKnightSettings& Settings);
	static void Upgrade4_4(CWebKnightSettings& Settings);
	static void Upgrade4_5(CWebKnightSettings& Settings);
	static void Upgrade4_6(CWebKnightSettings& Settings);
	static void Upgrade4_7(CWebKnightSettings& Settings);
};
