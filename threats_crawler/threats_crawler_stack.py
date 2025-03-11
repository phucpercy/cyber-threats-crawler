from aws_cdk import (
  Stack,
  aws_events as events,
  aws_lambda as _lambda, aws_iam as iam,
  aws_dynamodb as dynamodb, RemovalPolicy,
  aws_apigateway as apigateway, DockerImage, Duration,
)
from constructs import Construct


class ThreatsCrawlerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
      super().__init__(scope, construct_id, **kwargs)
      threat_crawler_lambda = self.create_threat_crawler_lambda()
      self.create_crawler_scheduler(threat_crawler_lambda, Duration.minutes(10))
      self.create_dynamodb_database()
      self.create_test_gateway(threat_crawler_lambda)


    def create_threat_crawler_lambda(self):
        threat_crawler_function = _lambda.Function(
            self,
            "MonitoringFunction",
            runtime=_lambda.Runtime.PYTHON_3_11,
            code=_lambda.Code.from_asset("threats_crawler/lambda",
                bundling={
                    'image': DockerImage.from_registry('python:3.11'),
                    'command': [
                        'bash', '-c',
                        'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output'
                    ],
                }
            ),
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

    def create_dynamodb_database(self):
      dynamodb.Table(
          self, "CyberThreatData",
          table_name="CyberThreatData",
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

    def create_crawler_scheduler(self, threat_lambda, duration):
      rule = events.Rule(
          self, "ThreatCrawlerRule",
          schedule=events.Schedule.rate(duration),
          targets=[threat_lambda]
      )