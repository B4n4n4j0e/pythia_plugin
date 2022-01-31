event zeek_init()
{
# Removes all default filters from active_streams
for (stream in Log::active_streams) {
      Log::remove_default_filter(stream);
      }

}