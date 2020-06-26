val o=spark.read.json("/var/log/vehere/ml-dnsalert/merge/four/mergeData-15min.json").withColumn("id", monotonically_increasing_id()).select(col("match_body"),col("match_body")("session")("num_app_protocol").as("numAppLabel"))
val m=o("numAppLabel").equalTo(53)
val n=o.filter(m)

val df4=n.select(col("match_body"),
              col("match_body")("session")("server_nonempty_packet_count").as("reverseNonEmptyPacketCount"),
              col("match_body")("session")("end_time_str").as("flowEndMilliseconds"),
              col("match_body")("session")("duration").as("flowDurationMilliseconds") ,
              col("match_body")("session")("id").as("flowKeyHash"),
              col("match_body")("transport")("dst_port").as("destinationTransportPort"),
              col("match_body")("network")("src_ip").as("sourceIPv4Address"),
              col("match_body")("session")("transmitted_bytes").as("dataByteCount"),
              col("match_body")("session")("received_bytes").as("reverseDataByteCount") ,
              col("match_body")("session")("client_nonempty_packet_count").as("nonEmptyPacketCount"),
              col("match_body")("transport")("src_port").as("sourceTransportPort"),
              col("match_body")("network")("dst_ip").as("destinationIPv4Address"),
              col("match_body")("payload")("dns_headers").as("dns_headers"))



val p4=df4.withColumn("id", monotonically_increasing_id())


val l4=p4.withColumn("dns_headers", explode(col("dns_headers")))

val m4=l4.filter((col("dns_headers")("rr_section")=== 0 ||col("dns_headers")("rr_section")=== 1)&&(col("dns_headers")("dns_record_type")===1 || col("dns_headers")("dns_record_type")===5 || col("dns_headers")("dns_record_type")===28))


val n4=m4.groupBy("id").agg(collect_list(col("dns_headers")),first("match_body").as("match_body"),first("reverseNonEmptyPacketCount").as("reverseNonEmptyPacketCount"),first("flowEndMilliseconds").as("flowEndMilliseconds"),first("flowDurationMilliseconds").as("flowDurationMilliseconds"),first("flowKeyHash").as("flowKeyHash"),first("destinationTransportPort").as("destinationTransportPort"),first("sourceIPv4Address").as("sourceIPv4Address"),first("dataByteCount").as("dataByteCount"),first("reverseDataByteCount").as("reverseDataByteCount"),first("nonEmptyPacketCount").as("nonEmptyPacketCount"),first("sourceTransportPort").as("sourceTransportPort"),first("destinationIPv4Address").as("destinationIPv4Address")).drop("id")

val r5=n4.withColumnRenamed("collect_list(dns_headers)", "dns_headers")

val q5=r5.withColumn("numberOfDNSRecords",size(col("dns_headers")))

val r4=q5.withColumn("dnsNXDomain",(col("dns_headers")("dns_response_code"))(col("numberOfDNSRecords")-1)).drop("numberOfDNSRecords")

val dft=r4.select(col("match_body"),
              col("reverseNonEmptyPacketCount"),
              col("flowEndMilliseconds"),
              col("flowDurationMilliseconds") ,
              col("flowKeyHash"),
              col("destinationTransportPort"),
              col("sourceIPv4Address"),
              col("dataByteCount"),
              col("reverseDataByteCount"),
              col("nonEmptyPacketCount"),
              col("sourceTransportPort"),
              col("destinationIPv4Address"),
              col("dnsNXDomain").as("dnsNXDomain"),
              (col("dns_headers")("rr_section"))(0).as("dnsRRSection"),
              (col("dns_headers")("dns_record_type"))(0).as("dnsQRType"),
              (col("dns_headers")("dns_domain_name"))(0).as("dnsQName"),
              (col("dns_headers")("cname"))(1).as("dnsQName2"),
              (col("dns_headers")("cname"))(2).as("dnsQName3"),
              (col("dns_headers")("cname"))(3).as("dnsQName4"),
              (col("dns_headers")("cname"))(4).as("dnsQName5"),
              (col("dns_headers")("cname"))(5).as("dnsQName6"),
              (col("dns_headers")("cname"))(6).as("dnsQName7"),
              (col("dns_headers")("cname"))(7).as("dnsQName8"),
              (col("dns_headers")("cname"))(8).as("dnsQName9"),
              (col("dns_headers")("cname"))(9).as("dnsQName10"),
              (col("dns_headers")("cname"))(10).as("dnsQName11"),
              (col("dns_headers")("cname"))(11).as("dnsQName12"),
              (col("dns_headers")("cname"))(12).as("dnsQName13"),
              (col("dns_headers")("cname"))(13).as("dnsQName14"),
              (col("dns_headers")("cname"))(14).as("dnsQName15"),
              (col("dns_headers")("cname"))(15).as("dnsQName16"),
              (col("dns_headers")("cname"))(16).as("dnsQName17"),
              (col("dns_headers")("cname"))(17).as("dnsQName18"),
              (col("dns_headers")("cname"))(18).as("dnsQName19"),
              (col("dns_headers")("cname"))(19).as("dnsQName20"),
              (col("dns_headers")("a_ip_address")).as("A"),
              (col("dns_headers")("ipv6_address")).as("AAAA"))




val top = spark.read.csv("/usr/local/bin/ml-analyzer/top-1m.csv").select("_c1")
val TopLevelDomainName = spark.read.csv("/usr/local/bin/ml-analyzer/top-1m-TLD.csv").select("_c1")

val slice = udf((array : Seq[String], from : Int, to : Int) => array.slice(from,to))


val a1= df.withColumn("array", split($"dnsQName", "\\."))
val b1=a1.withColumn("length", size($"array"))
val f1=b1.withColumn("suffix1", concat_ws(".", ($"array")(col("length")-3),($"array")(col("length")-2)))
val y1=f1.withColumn("slice", slice($"array", lit($"length"-4), lit($"length"-1)))
val x1=y1.withColumn("suffix2", concat_ws(".", $"slice")).drop("slice")
val c1=x1.withColumn("slice", slice($"array", lit($"length"-5), lit($"length"-1)))
val d1=c1.withColumn("suffix3", concat_ws(".", $"slice")).drop("slice")
val g1=d1.withColumn("slice", slice($"array", lit($"length"-6), lit($"length"-1)))
val h1=g1.withColumn("suffix4", concat_ws(".", $"slice")).drop("slice")
val z1=h1.withColumn("slice", slice($"array", lit(0), lit($"length"-1)))
val t1=z1.withColumn("Fquery", concat_ws(".", $"slice")).drop("slice")

val u1=t1.join(top, t1("Fquery")=== top("_c1"), "left_outer").withColumnRenamed("_c1", "topquery").join(top, t1("suffix1")=== top("_c1"), "left_outer").withColumnRenamed("_c1", "Suffixquery1").join(top, t1("suffix2")=== top("_c1"), "left_outer").withColumnRenamed("_c1", "Suffixquery2").join(top, t1("suffix3")=== top("_c1"), "left_outer").withColumnRenamed("_c1", "Suffixquery3").join(top, t1("suffix4")=== top("_c1"), "left_outer").withColumnRenamed("_c1", "Suffixquery4").join(TopLevelDomainName, t1("suffix1")=== TopLevelDomainName("_c1"), "left_outer")

val ut1=u1.withColumn("suffix",when(col("Fquery")===col("topquery"),col("Fquery")).when((col("suffix1")===col("_c1") || col("suffix1")===col("Suffixquery1")),col("suffix1")).when( col("suffix2")===col("Suffixquery2"),col("suffix2")).when(col("suffix3")===col("Suffixquery3"),col("suffix3")).when(col("suffix4")===col("Suffixquery4"),col("suffix4")).otherwise(col("suffix1")))

val uq1=ut1.withColumn("queryScore", when(col("Fquery")===col("topquery"),2).when((col("suffix1")===col("_c1") || col("suffix1")===col("Suffixquery1") || col("suffix2")===col("Suffixquery2") || col("suffix3")===col("Suffixquery3") || col("suffix4")===col("Suffixquery4")),1).otherwise(0)).drop("_c1", "suffix1","suffix2","suffix3","suffix4","Fquery","topquery","Suffixquery1","Suffixquery2","Suffixquery3","Suffixquery4")

val gt=uq1.withColumn("arr", split($"suffix", "\\."))
val bt=gt.withColumn("len", size($"arr"))
val xz=bt.withColumn("slice", slice($"array", lit(0), lit($"length"-$"len"-1)))
 val tempquery=xz.withColumn("prefix", concat_ws(".", $"slice")).drop("slice","arr","len","array","length")


val xa=tempquery.select("suffix","prefix").withColumnRenamed("suffix","sf")
val xb1=xa.filter(col("prefix")isNotNull)
val xb2=xb1("prefix").notEqual("")
val xb=xb1.filter(xb2)
val xc=xb.dropDuplicates.groupBy("sf").count
val xd=tempquery.join(xc,tempquery("suffix")===xc("sf"),"leftouter").drop("sf")
val xe=xd.withColumn("prefixSuffixRatio",when(col("count")isNull,0).otherwise(col("count"))).drop("count")




val xf=xe.select("A","dnsQName").withColumn("A",explode(col("A"))).withColumnRenamed("dnsQName","dnsName")
val xg=xf.filter(col("A")isNotNull)
val xh=xg.dropDuplicates.groupBy("dnsName").count
val xi=xe.join(xh,xe("dnsQName")===xh("dnsName"),"leftouter").drop("dnsName")
val xj1=xi.withColumn("fullQueryIPCount1",when(col("count")isNull,0).otherwise(col("count"))).drop("count")

val xf1=xj1.select("AAAA","dnsQName").withColumn("AAAA",explode(col("AAAA"))).withColumnRenamed("dnsQName","dnsName")
val xg1=xf1.filter(col("AAAA")isNotNull)
val xh1=xg1.dropDuplicates.groupBy("dnsName").count
val xi1=xj1.join(xh1,xj1("dnsQName")===xh1("dnsName"),"leftouter").drop("dnsName")
val xj2=xi1.withColumn("fullQueryIPCount2",when(col("count")isNull,0).otherwise(col("count"))).drop("count")

val xj=xj2.withColumn("fullQueryIPCount",col("fullQueryIPCount1")+ col("fullQueryIPCount2"))


val xk=xj.select("A","suffix").withColumn("A",explode(col("A"))).withColumnRenamed("suffix","sf")
val xl=xk.filter(col("A")isNotNull)
val xm=xl.dropDuplicates.groupBy("sf").count
val xn=xj.join(xm,xj("suffix")===xm("sf"),"leftouter").drop("sf")
val xo1=xn.withColumn("suffixQueryIPCount1",when(col("count")isNull,0).otherwise(col("count"))).drop("count")


val xk1=xo1.select("AAAA","suffix").withColumn("AAAA",explode(col("AAAA"))).withColumnRenamed("suffix","sf")
val xl1=xk1.filter(col("AAAA")isNotNull)
val xm1=xl1.dropDuplicates.groupBy("sf").count
val xn1=xo1.join(xm1,xo1("suffix")===xm1("sf"),"leftouter").drop("sf")
val xo2=xn1.withColumn("suffixQueryIPCount2",when(col("count")isNull,0).otherwise(col("count"))).drop("count")


val xo=xo2.withColumn("suffixQueryIPCount",col("suffixQueryIPCount1")+col("suffixQueryIPCount2"))


val query=xo.withColumn("query",concat(col("prefixSuffixRatio"),lit("_"),col("fullQueryIPCount"),lit("_"),col("suffixQueryIPCount")))
              

query.write.mode("overwrite").json("/var/log/vehere/ml-dnsalert/filter/data")



