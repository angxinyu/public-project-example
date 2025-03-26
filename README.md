# public-project-example
## 项目示例代码

### Smart-Fitness-Assistant
- Core code example
```agsl
package com.example.smartfitnessassistant.service;

import com.alibaba.dashscope.aigc.generation.Generation;
import com.alibaba.dashscope.aigc.generation.GenerationParam;
import com.alibaba.dashscope.aigc.generation.GenerationResult;
import com.alibaba.dashscope.common.Message;
import com.alibaba.dashscope.common.Role;
import com.alibaba.dashscope.exception.ApiException;
import com.alibaba.dashscope.exception.InputRequiredException;
import com.alibaba.dashscope.exception.NoApiKeyException;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * @author wxy
 */
@Service
public class OpenAIService {
  private final Map<String,GenerationResult> cache=new ConcurrentHashMap<>();
  public GenerationResult callWithMessage(String question) throws ApiException, NoApiKeyException, InputRequiredException {
    if(cache.containsKey(question)){
      return cache.get(question);
    }

    Generation gen = new Generation();
    Message systemMsg = Message.builder()
        .role(Role.SYSTEM.getValue())
        .content("You are a helpful assistant.")
        .build();
    Message userMsg = Message.builder()
        .role(Role.USER.getValue())
        .content(question)
        .build();
    GenerationParam param = GenerationParam.builder()
        // 若没有配置环境变量，请用百炼API Key将下行替换为：.apiKey("sk-xxx")
        .apiKey("sk-c46828f9c63f47c7ab2baca2f41f82f4")
        .model("qwen-plus")
        .messages(Arrays.asList(systemMsg, userMsg))
        .resultFormat(GenerationParam.ResultFormat.MESSAGE)
        .build();
    cache.put(question,gen.call(param));
    return gen.call(param);
  }
}

```
### Distributed-Fault-Injection
- Core code example
```agsl
package core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import event.*;




public class FaultInjector {

    // 模拟流量注入
    public void injectTrafficFault() {

        // 调用JNI方法来发送错误数据包
        // 假设有一个nativeLib库中的nativeMethod方法用于发送错误包
        PacketInjector.injectFaultyPacket();
    }

    // 模拟启停测试
    public void injectKillFault() {
        try {
            // 调用shell脚本来杀死服务器进程
            // 假设shell脚本在 /path/to/kill_script.sh
            Runtime.getRuntime().exec("/path/to/kill_script.sh");
        } catch (IOException e) {
            // 处理异常
            e.printStackTrace();
        }
    }

    // 模拟参数故障
    public void injectConfigurationFault(String configFilePath, String newConfig) {
        try {
            // 修改配置文件
            Files.write(Paths.get(configFilePath), newConfig.getBytes());
            // 重启Spring服务
            // 这里假设有一个restartSpringService的shell脚本
            Runtime.getRuntime().exec("/path/to/restart_spring_service.sh");
        } catch (IOException e) {
            // 处理异常
            e.printStackTrace();
        }
    }

    // 加载本地库，这里需要替换为实际的库名
    static {
        System.loadLibrary("nativeLib");
    }

    // 声明native方法，这里需要替换为实际的方法签名
    private native void nativeMethod();
}
```
```agsl
package core;
import config.EnvironmentConfig;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
public class ProxyServer {
    private final int port;
    private final ProxyHandler proxyHandler;
    private final EnvironmentConfig config;

    private Bootstrap bootstrapTestEnv;
    private Bootstrap bootstrapOrigTar;
    private final ChannelInboundHandler httpServerHandler;


    public ProxyServer(int port, ProxyHandler proxyHandler, Bootstrap bootstrapTestEnv, Bootstrap bootstrapOrigTar,EnvironmentConfig config, ChannelInboundHandler httpServerHandler) {
        this.port = port;
        this.proxyHandler = proxyHandler;
        this.bootstrapTestEnv = bootstrapTestEnv;
        this.bootstrapOrigTar = bootstrapOrigTar;
        this.config = config;
        this.httpServerHandler = httpServerHandler;
    }

    public void start() throws Exception {
        EventLoopGroup bossGroup = new NioEventLoopGroup();
        EventLoopGroup workerGroup = new NioEventLoopGroup();
        try {
            ServerBootstrap bootstrap = new ServerBootstrap();
            bootstrap.group(bossGroup, workerGroup)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel ch) {
                            // 在这里，我们不立即创建 EnvironmentBehavior 实例
                            // 而是将 Bootstrap 实例和配置传递给 ProxyHandler
                            ch.pipeline().addLast(new ProxyHandler(bootstrapTestEnv, bootstrapOrigTar, config));
                            ch.pipeline().addLast(new HttpServerCodec());
                            ch.pipeline().addLast(new HttpObjectAggregator(65536));
                            ch.pipeline().addLast(httpServerHandler);
                        }
                    })
                    .option(ChannelOption.SO_BACKLOG, 128)
                    .childOption(ChannelOption.SO_KEEPALIVE, true);

            // 绑定并开始接受传入的连接
            ChannelFuture bindFuture = bootstrap.bind(port).sync();
            bindFuture.channel().closeFuture().sync();
        } finally {
            workerGroup.shutdownGracefully();
            bossGroup.shutdownGracefully();
        }
    }
        public static void main(String[] args) throws Exception {
            ApplicationContext context = new AnnotationConfigApplicationContext("config");
            EnvironmentConfig config = context.getBean(EnvironmentConfig.class);

            // 创建Bootstrap实例
            Bootstrap bootstrapTestEnv = config.createBootstrapForTestEnv(null); // 这里传入null作为ChannelHandler，稍后设置
            Bootstrap bootstrapOrigTar = config.createBootstrapForOrigTarEnv(null); // 同上

            // 连接到测试环境和原始目标环境
            ChannelFuture testEnvChannelFuture = bootstrapTestEnv.connect();
            ChannelFuture origTarChannelFuture = bootstrapOrigTar.connect();

            // 确保连接完成
            Channel testEnvironmentChannel = testEnvChannelFuture.sync().channel();
            Channel originalTargetChannel = origTarChannelFuture.sync().channel();
            // 创建ProxyHandler实例，它将会根据环境配置的不同来决定具体的行为
            ProxyHandler handler;
            EnvironmentBehavior testEnvBehavior = new ProjectEnvironmentBehavior(config, testEnvironmentChannel, originalTargetChannel);
            EnvironmentBehavior origTarBehavior = new ProjectEnvironmentBehavior(config, testEnvironmentChannel, originalTargetChannel);
            if ("project".equals(config.getEnvironment())) {
                handler = new ProjectEnvironmentProxyHandler(bootstrapTestEnv, bootstrapOrigTar, config, testEnvironmentChannel, originalTargetChannel);
            } else if ("test".equals(config.getEnvironment())) {
                // 这里需要传入所有必要的参数来创建TestEnvironmentProxyHandler实例
                handler = new TestEnvironmentProxyHandler(bootstrapTestEnv, bootstrapOrigTar, config);
            } else {
                throw new IllegalArgumentException("Invalid environment: " + config.getEnvironment());
            }

            // 使用创建好的ChannelHandler来更新Bootstrap实例
            bootstrapTestEnv.handler(handler);
            bootstrapOrigTar.handler(handler);

            FaultInjector faultInjector = new FaultInjector(); // 使用适当的构造函数
            int port = config.getProxyServerPort();
            ProjectEnvironmentProxyHandler proxyHandler = new ProjectEnvironmentProxyHandler(bootstrapTestEnv, bootstrapOrigTar, config, testEnvironmentChannel, originalTargetChannel);
            ChannelInboundHandler httpServerHandler = new HttpServerHandler(proxyHandler,faultInjector, config);

            // 创建并启动代理服务器
            new ProxyServer(port, handler, bootstrapTestEnv, bootstrapOrigTar, config, httpServerHandler).start();
        }

    }
```
### DTS
- Core code example
```agsl
import com.alicp.jetcache.Cache;
import com.gitee.dbswitch.common.converter.ConverterFactory;
import com.gitee.dbswitch.common.entity.CloseableDataSource;
import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import com.inventec.dts.admin.common.response.PageResult;
import com.inventec.dts.admin.controller.convert.AssignmentInfoConverter;
import com.inventec.dts.admin.dao.UpdateJobDataSyncDAO;
import com.inventec.dts.admin.entity.DatabaseConnectionEntity;
import com.inventec.dts.admin.model.request.UpdateAssignmentRequest;
import com.inventec.dts.admin.model.response.AssignmentInfoResponse;
import com.inventec.dts.admin.type.ZoneEnum;
import com.inventec.dts.admin.util.CacheUtil;
import com.inventec.dts.admin.util.PageUtils;
import com.inventec.dts.core.exception.DbSyncException;
import com.inventec.dts.core.job.kettle.KettleJobConfig;
import com.inventec.dts.core.mannager.DatasourceManager;
import com.inventec.dts.core.type.SyncMode;
import jakarta.annotation.Resource;
import java.lang.reflect.Type;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;


/**
 * @author wxy
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class DtsLoadTaskListService {

  private final DtsConnectionService dtsConnectionService;

  @Autowired
  private JdbcTemplate jdbcTemplate;

  private static final String QUERY_JOB_DATA_SYNC_BY_SRC_DB_NAME = "SELECT * FROM manager.job_data_sync;";

  private static final String DELETE_JOB_DATA_SYNC_BY_JOB_ID = "DELETE FROM manager.job_data_sync WHERE job_id = ?;";

  private static final String SELECT_JOB_DATA_SYNC_BY_SRC_DB_NAME = "SELECT * FROM manager.job_data_sync WHERE job_id = ?;";

  private static final Duration TIMEOUT_DURATION = Duration.ofSeconds(20);

  @Resource
  UpdateJobDataSyncDAO updateJobDataSyncDAO;

  @Autowired
  private CacheUtil cacheUtil;

  private static CloseableDataSource dataSource;

  public PageResult<AssignmentInfoResponse> listAll(Integer page, Integer size, ZoneEnum zone, boolean downstream) {
    ExecutorService executor = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    if (Objects.isNull(zone) || "".equals(zone.toString())) {
      throw new DbSyncException(ERROR_INVALID_ARGUMENT, "zone不能为空");
    }
    Callable<PageResult<AssignmentInfoResponse>> task = () -> {
      LocalDateTime startTime = LocalDateTime.now();
      //根据zone获取到的是DTS数据库中的所有数据连接
      List<DatabaseConnectionEntity> targetDatabaseConnections = dtsConnectionService.getConnectionByZone(downstream,
          String.valueOf(zone));

      List<AssignmentInfoResponse> response = new ArrayList<>();

      for (DatabaseConnectionEntity targetDatabaseConnection : targetDatabaseConnections) {
        Cache<String, List<AssignmentInfoResponse>> jetCache = cacheUtil.getJetCache();
        String cacheKey = zone + ":" + targetDatabaseConnection.getId();
        if (jetCache.get(cacheKey) != null) {
          List<AssignmentInfoResponse> cacheResponse = jetCache.get(cacheKey);
          response.addAll(cacheResponse);
        } else {
          dataSource = DatasourceManager.getDatasource(
              dtsConnectionService.getDataSourceInfo(targetDatabaseConnection.getId()));
          jdbcTemplate = new JdbcTemplate(dataSource);
          List<KettleJobConfig> entities = jdbcTemplate.query(
              QUERY_JOB_DATA_SYNC_BY_SRC_DB_NAME,
              (rs, rowNum) -> mapResultSetToJobDataSyncEntity(rs)
          );
          List<AssignmentInfoResponse> currentResponse = ConverterFactory.getConverter(
              AssignmentInfoConverter.class).convertAssignment(targetDatabaseConnection, entities);
          response.addAll(currentResponse);
          jetCache.put(cacheKey, currentResponse);
        }
      }
      LocalDateTime endTime = LocalDateTime.now();
      Duration duration = Duration.between(startTime, endTime);
      System.out.println("Time taken: " + duration.toMillis() + " ms");
      return PageUtils.getSortedPage(response, page, size,
          Comparator.comparing(AssignmentInfoResponse::getJobId, Comparator.nullsLast(Comparator.naturalOrder())));
    };
    //超时保护
    Future<PageResult<AssignmentInfoResponse>> future = executor.submit(task);
    try {
      return future.get(TIMEOUT_DURATION.toMillis(), TimeUnit.MILLISECONDS);
    } catch (TimeoutException e) {
      future.cancel(true);
      throw new DbSyncException(ERROR_INTERNAL_ERROR, "Timeout Exception:" + e.getMessage());
    } catch (Exception e) {
      throw new DbSyncException(ERROR_INTERNAL_ERROR, "Other Exception:" + e.getMessage());
    } finally {
      executor.shutdown();
    }
  }

  private KettleJobConfig mapResultSetToJobDataSyncEntity(ResultSet rs) throws SQLException {
    KettleJobConfig entity = new KettleJobConfig();
    entity.setJobId(rs.getInt("job_id"));
    entity.setSrcSchemaName(rs.getString("src_schema_name"));
    entity.setSrcTableName(rs.getString("src_table_name"));
    entity.setDstSchemaName(rs.getString("dst_schema_name"));
    entity.setDstTableName(rs.getString("dst_table_name"));
    entity.setSrcSelectStatement(rs.getString("src_select_statement"));
    entity.setSrcWhereStatement(rs.getString("src_where_statement"));
    entity.setSyncMode(rs.getString("sync_mode").toUpperCase());
    entity.setSrcIncrField(rs.getString("src_incr_field"));
    entity.setDstPk(rs.getString("dst_pk"));
    entity.setDstDistributedBy(rs.getString("dst_distributed_by"));

    String jsonMapping = rs.getString("fields_mapping");
    Map<String, String> fieldsMapping = null;
    if (jsonMapping != null) {
      Gson gson = new Gson();
      Type typeOfMap = new TypeToken<Map<String, String>>() {
      }.getType();
      fieldsMapping = gson.fromJson(jsonMapping, typeOfMap);
    }
    entity.setFieldsMapping(fieldsMapping);

    entity.setIncrPoint(rs.getString("incr_point"));
    entity.setCdt(rs.getTimestamp("cdt").toLocalDateTime());
    entity.setUdt(rs.getTimestamp("udt").toLocalDateTime());
    entity.setRemark(rs.getString("remark"));
    entity.setInuse(rs.getBoolean("inuse"));
    entity.setJobName(rs.getString("job_name"));
    entity.setSrcDbName(rs.getString("src_db_name"));
    entity.setSrcConnId(rs.getLong("src_conn_id"));

    return entity;
  }

  public AssignmentInfoResponse update(String dstConnIdAndJobId, UpdateAssignmentRequest request) {
    if (!dstConnIdAndJobId.contains("-")) {
      throw new DbSyncException(ERROR_INVALID_ARGUMENT, "dstConnIdAndJobId不可不存在-");
    }
    String[] dstConnIdAndJobIdArray = dstConnIdAndJobId.split("-");
    Long dstConnId = (long) Integer.parseInt(dstConnIdAndJobIdArray[0]);
    int jobId = Integer.parseInt(dstConnIdAndJobIdArray[1]);
    DatabaseConnectionEntity targetDatabaseConnection = dtsConnectionService.getConnection(
        dstConnId);
    AssignmentInfoResponse updateResponse = null;
    dataSource = DatasourceManager.getDatasource(
        dtsConnectionService.getDataSourceInfo(targetDatabaseConnection.getId()));
    try {
      jdbcTemplate = new JdbcTemplate(dataSource);
      List<Object> parameters = new ArrayList<>();
      String sql = updateJobDataSyncDAO.buildUpdateJobDataSyncSql(parameters, request, jobId);
      int rowsAffected = jdbcTemplate.update(sql, parameters.toArray());
      if (rowsAffected > 0) {
        Cache<String, List<AssignmentInfoResponse>> jetCache = cacheUtil.getJetCache();
        String cacheKey = targetDatabaseConnection.getZone() + ":" + targetDatabaseConnection.getId();
        jetCache.remove(cacheKey);
        List<KettleJobConfig> entity = jdbcTemplate.query(
            SELECT_JOB_DATA_SYNC_BY_SRC_DB_NAME,
            new Object[]{jobId},
            (rs, rowNum) -> mapResultSetToJobDataSyncEntity(rs)
        );
        if (!entity.isEmpty()) {
          KettleJobConfig updatedEntity = entity.get(0);
          updateResponse = new AssignmentInfoResponse();
          BeanUtils.copyProperties(updatedEntity, updateResponse);
          updateResponse.setJobId(targetDatabaseConnection.getId() + "-" + updatedEntity.getJobId());
          updateResponse.setSyncMode(SyncMode.valueOf(updatedEntity.getSyncMode()));
          String dstPk = updatedEntity.getDstPk();
          List<String> dstPkList = new ArrayList<>();
          if (dstPk != null) {
            dstPkList = Arrays.stream(dstPk.split(",")).filter(s -> !s.isEmpty()).collect(Collectors.toList());
          }
          updateResponse.setDstPk(dstPkList.isEmpty() ? new ArrayList<>() : dstPkList);
          updateResponse.setDstConnId(targetDatabaseConnection.getId());
          updateResponse.setDstDbName(targetDatabaseConnection.getDatabaseName());
        }
      }
    } catch (Exception e) {
      log.error("update assignment error", e);
      throw new DbSyncException(e.getMessage());
    }
    return updateResponse;
  }

  public void deleteByJobId(String dstConnIdAndJobId) {
    if (!dstConnIdAndJobId.contains("-")) {
      throw new DbSyncException(ERROR_INVALID_ARGUMENT, "dstConnIdAndJobId不可不存在-");
    }
    String[] dstConnIdAndJobIdArray = dstConnIdAndJobId.split("-");
    Long dstConnId = (long) Integer.parseInt(dstConnIdAndJobIdArray[0]);
    int jobId = Integer.parseInt(dstConnIdAndJobIdArray[1]);
    DatabaseConnectionEntity targetDatabaseConnection = dtsConnectionService.getConnection(
        dstConnId);
    dataSource = DatasourceManager.getDatasource(
        dtsConnectionService.getDataSourceInfo(targetDatabaseConnection.getId()));
    try {
      jdbcTemplate = new JdbcTemplate(dataSource);
      int rowsAffected = jdbcTemplate.update(DELETE_JOB_DATA_SYNC_BY_JOB_ID, jobId);
      if (rowsAffected > 0) {
        Cache<String, List<AssignmentInfoResponse>> jetCache = cacheUtil.getJetCache();
        String cacheKey = targetDatabaseConnection.getZone() + ":" + targetDatabaseConnection.getId();
        jetCache.remove(cacheKey);
      }
    } catch (Exception e) {
      log.error("delete assignment error", e);
      throw new DbSyncException(e.getMessage());
    }
  }
}

```