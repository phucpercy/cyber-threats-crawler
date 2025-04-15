from aws_cdk import (
  Stack,
  aws_events as events,
  aws_events_targets as events_targets,
  aws_lambda as _lambda, aws_iam as iam,
  aws_dynamodb as dynamodb, RemovalPolicy,
  aws_apigateway as apigateway, Duration,
)
from constructs import Construct


class ThreatsCrawlerStack(Stack):

  def __init__(self, scope: Construct, construct_id: str, stage_name: str, **kwargs) -> None:
    super().__init__(scope, construct_id, **kwargs)
    threat_crawler_lambda = self.create_threat_crawler_lambda(stage_name)
    self.create_crawler_scheduler(threat_crawler_lambda, Duration.minutes(10), stage_name)
    self.create_dynamodb_database(stage_name)
    # self.create_test_gateway(threat_crawler_lambda)

  def create_threat_crawler_lambda(self, stage_name: str):
    threat_crawler_function = _lambda.Function(
        self,
        stage_name + "MonitoringFunction",
        runtime=_lambda.Runtime.PYTHON_3_11,
        code=_lambda.Code.from_asset("threats_crawler/lambda"),
        handler="threats_crawler.lambda_handler",
        initial_policy=[
          iam.PolicyStatement(
              effect=iam.Effect.ALLOW,
              actions=[
                'cloudwatch:PutMetricData',
                'cloudwatch:PutDashboard',
                'cloudwatch:PutMetricAlarm',
                'cloudwatch:DescribeAlarms',
                'cloudwatch:DeleteAlarms',
                'dynamodb:*'
              ],
              resources=['*', ],
          )
        ]
    )
    return threat_crawler_function

  def create_dynamodb_database(self, stage_name: str):
    dynamodb.Table(
        self, "CyberThreatData",
        table_name=stage_name + "CyberThreatData",
        partition_key=dynamodb.Attribute(
            name="ThreatID",
            type=dynamodb.AttributeType.STRING
        ),
        read_capacity=5,
        write_capacity=5,
        removal_policy=RemovalPolicy.DESTROY
    )

  def create_test_gateway(self, threat_lambda):
    apigateway.LambdaRestApi(
        self, "ThreatApiGateway",
        rest_api_name="CyberThreatApi",
        handler=threat_lambda,  # API calls will trigger this Lambda
        proxy=True  # Proxy integration sends all requests to the Lambda
    )

  def create_crawler_scheduler(self, threat_lambda, duration, stage_name: str):
    events.Rule(
        self, "ThreatCrawlerRule",
        rule_name=stage_name + "ThreatCrawlerScheduler",
        schedule=events.Schedule.rate(duration),
        targets=[events_targets.LambdaFunction(handler=threat_lambda,)],
    )
