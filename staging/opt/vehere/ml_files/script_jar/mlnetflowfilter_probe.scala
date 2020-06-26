import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._
import sys.process._
val sqlContext = new org.apache.spark.sql.SQLContext(sc)



val a3=spark.read.json("/var/log/vehere/ml-alert/merge/mergeData.json")

val b3=a3.select(col("match_body"),col("match_body")("payload")("dns_headers").as("dns_headers"),col("match_body")("session")("term_clause").as("flowEndReason"),col("match_body")("session")("num_app_protocol").as("numAppLabel"),col("match_body")("session")("end_time_str").as("flowEndMilliseconds"),col("match_body")("session")("start_time_str").as("flowStartMilliseconds"),col("match_body")("network")("transport_protocol_num").as("protocolIdentifier"),col("match_body")("session")("duration").as("flowDurationMilliseconds") ,col("match_body")("session")("id").as("flowKeyHash"),col("match_body")("transport")("dst_port").as("destinationTransportPort"),col("match_body")("network")("src_ip").as("sourceIPv4Address") ,col("match_body")("session")("transmitted_bytes").as("dataByteCount"),col("match_body")("session")("received_bytes").as("reverseDataByteCount") ,col("match_body")("session")("client_nonempty_packet_count").as("nonEmptyPacketCount"),col("match_body")("transport")("src_port").as("sourceTransportPort"),col("match_body")("network")("dst_ip").as("destinationIPv4Address"),
col("match_body")("session")("transmitted_packets").as("packetTotalCount"),col("match_body")("session")("received_packets").as("reversePacketTotalCount"),col("match_body")("session")("dpi_num_master_protocol").as("nDPIL7Protocol"),col("match_body")("session")("dpi_num_app_protocol").as("nDPIL7SubProtocol"))

val c3=spark.read.json("/var/log/vehere/ml-alert/merge/summaryData.json")

val d3=c3.select(col("num_app_protocol").as("AppLabel"),col("src_ip").as("sourceIP"),col("srcAsn").as("srcAsn"),col("dstAsn").as("dstAsn"),col("dpi_num_master_protocol").as("nDPIL7"),col("dpi_num_app_protocol").as("nDPIL7Sub"),col("summaryData1h").as("summaryData1h"),col("summaryData8h").as("summaryData8h"),col("summaryData1d").as("summaryData1d"),col("summaryData1w").as("summaryData1w"))


val p1=b3.join(d3,(b3("sourceIPv4Address")===d3("sourceIP") && b3("numAppLabel")===d3("AppLabel") && b3("nDPIL7Protocol")===d3("nDPIL7") && b3("nDPIL7SubProtocol")===d3("nDPIL7Sub")),"inner").drop("sourceIP","AppLabel","nDPIL7","nDPIL7Sub")



val z12=p1




val z1=z12.withColumn("dstAsno",col("dstAsn").cast("Long")).withColumn("dstAsno",when(col("dstAsno")isNull,0).otherwise(col("dstAsno"))).withColumn("srcAsn",col("srcAsn").cast("Long")).withColumn("srcAsn",when(col("srcAsn")isNull,0).otherwise(col("srcAsn")))



val az=p1.filter(col("numAppLabel")===53).select(col("dns_headers")("a_ip_address").as("A")).withColumn("A",explode(col("A")))
val a=az.filter(col("A")isNotNull)
val b=a.groupBy("A").count.withColumnRenamed("count","queryCount1")
val g3=z1.join(b,z1("destinationIPv4Address")===b("A"),"leftouter").withColumn("queryCount1",when(col("queryCount1")isNull,0).otherwise(col("queryCount1")))




val e3=p1.filter(col("numAppLabel")===53).select(col("dns_headers")("ipv6_address").as("AAAA")).withColumn("AAAA",explode(col("AAAA")))
val f3=e3.filter(col("AAAA")isNotNull)
val h3=f3.groupBy("AAAA").count.withColumnRenamed("count","queryCount2")
val i3=g3.join(h3,g3("destinationIPv4Address")===h3("AAAA"),"leftouter").withColumn("queryCount2",when(col("queryCount2")isNull,0).otherwise(col("queryCount2")))

val c=i3.withColumn("queryCount",when(col("destinationIPv4Address")===col("A"),col("queryCount1")).when(col("destinationIPv4Address")===col("AAAA"),col("queryCount2")).otherwise(0))





val d=c.withColumn("Durationseconds",col("flowDurationMilliseconds")*lit(1000))


val e=d.withColumn("unix_tstamp", (unix_timestamp($"flowStartMilliseconds", "yyyy-MM-dd HH:mm:ss.SSS"))*lit(1000000)).orderBy("unix_tstamp")

import org.apache.spark.sql.expressions.Window
val w = Window.orderBy($"sourceIPv4Address")

val xz1=e.withColumn("prev_value",when($"sourceIPv4Address" === lag($"sourceIPv4Address", 1).over(w), lag($"unix_tstamp", 1).over(w))).withColumn("sessionGap",col("unix_tstamp")-col("prev_value")).withColumn("sessionGap",when(col("sessionGap")isNull,0).otherwise(col("sessionGap"))).drop("prev_value","unix_tstamp")

val x=xz1.withColumn("NDP1",concat(col("nDPIL7Protocol"),col("nDPIL7SubProtocol"))).withColumn("NDP1",when(col("NDP1")==="00",0).otherwise(col("NDP1"))).withColumn("NDP1",col("NDP1").cast("Long")).withColumn("ndpiValue",col("NDP1"))




val f=x("ndpiValue").notEqual(0)
val dfNotNull=x.filter(f)

val dfNull =x.filter(col("ndpiValue")===0)

val dfNotNullRenamed = dfNotNull.
    withColumnRenamed("ndpiValue", "ndp").
    withColumnRenamed("flowStartMilliseconds", "flow").
    withColumnRenamed("sourceIPv4Address", "sourceIP").
    select("ndp", "sourceIP","flow")

val joinedWithFuture = dfNull.join(
  dfNotNullRenamed, x("sourceIPv4Address") <=> dfNotNullRenamed("sourceIP") && dfNotNullRenamed("ndp") >=x("ndpiValue"),"left_outer").withColumn("ndpiValue", coalesce($"ndp", $"ndpiValue")).drop("ndp").drop("sourceIP")

joinedWithFuture.registerTempTable("joined_with_future")

val query = """SELECT * FROM (SELECT *, row_number() OVER (
  PARTITION BY flowStartMilliseconds
  ORDER BY ABS(CAST(timestamp(flow) as INT) - CAST(timestamp(flowStartMilliseconds) as INT))
) rn FROM joined_with_future) tmp WHERE rn = 1"""

val g = sqlContext.
  sql(query).
  drop("rn").
  drop("flow").
  unionAll(dfNotNull).
  orderBy("sourceIPv4Address")


val g6=g.withColumn("NDP2",col("ndpiValue"))


val i6=g6("ndpiValue").notEqual(0)
val a61=g6.filter(i6)

val b61 =g6.filter(col("ndpiValue")===0)

  val a6Renamed1 = a61.withColumnRenamed("ndpiValue", "ndp").
    withColumnRenamed("flowStartMilliseconds", "flow").
    withColumnRenamed("srcAsn", "AsnNo").
    select("ndp", "AsnNo","flow")

val c61 = b61.join(
  a6Renamed1, g6("srcAsn") <=> a6Renamed1("AsnNo") && a6Renamed1("ndp") >=g6("ndpiValue"),"left_outer").withColumn("ndpiValue", coalesce($"ndp", $"ndpiValue")).drop("ndp").drop("AsnNo")

c61.registerTempTable("joined_with_future")

val d61 = """SELECT * FROM (SELECT *, row_number() OVER (
  PARTITION BY flowStartMilliseconds
  ORDER BY ABS(CAST(timestamp(flow) as INT) - CAST(timestamp(flowStartMilliseconds) as INT))
) rn FROM joined_with_future) tmp WHERE rn = 1"""


val dfNullImputed = sqlContext.
  sql(d61).
  drop("rn").
  drop("flow").
  unionAll(a61).
  orderBy("srcAsn")


val h=dfNullImputed.withColumn("ndpiType",when((col("NDP1")===col("NDP2") && col("NDP2")===col("ndpiValue")),0).when(col("NDP2")===col("ndpiValue"),1).otherwise(2))



h.write.mode("overwrite").json("/var/log/vehere/ml-alert/filter")

