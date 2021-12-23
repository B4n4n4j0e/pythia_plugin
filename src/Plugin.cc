
#include "Plugin.h"

namespace plugin { namespace Prod_Pythia { Plugin plugin; } }

using namespace plugin::Prod_Pythia;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Prod::Pythia";
	config.description = "Creates hourly summaries and stores data in a sqlite3 database. Normally used together with the visualisation tool pythia https://github.com/B4n4n4j0e/pythia/";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;
	return config;
	}
