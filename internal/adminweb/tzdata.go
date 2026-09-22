package adminweb

// The console renders every timestamp in whichever named time zone the
// administrator selected. The production image is distroless and ships no
// zoneinfo database, so `time.LoadLocation` would fail for every name but "UTC"
// and the setting would silently collapse back to UTC. Embedding the database
// here keeps the setting working wherever the binary runs; it costs a few
// hundred kilobytes and nothing else in the server links this package.
import _ "time/tzdata"
