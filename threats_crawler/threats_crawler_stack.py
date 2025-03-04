from aws_cdk import (
  Stack,
  aws_lambda as _lambda, Duration,
  aws_iam as iam,
  aws_dynamodb as dynamodb, RemovalPolicy,
  aws_apigatewayv2 as apigateway,
)
from constructs import Construct


class ThreatsCrawlerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
      super().__init__(scope, construct_id, **kwargs)
      threat_crawler_lambda = self.create_threat_crawler_lambda()
      self.create_dynamodb_database()
      self.create_test_gateway(threat_crawler_lambda)


    def create_threat_crawler_lambda(self):
        threat_crawler_function = _lambda.Function(
            self,
            "MonitoringFunction",
            runtime=_lambda.Runtime.PYTHON_3_11,
            code=_lambda.Code.from_asset("canary_monitoring/lambda"),
            handler="resources_monitor.measuring_handler",
            timeout=Duration.seconds(60),
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
          removal_policy=RemovalPolicy.DESTROY  # Use DESTROY for dev; change to RETAIN for production
      )

    def create_test_gateway(self, threat_lambda):
      apigateway.LambdaRestApi(
          self, "ThreatApiGateway",
          rest_api_name="CyberThreatApi",
          handler=threat_lambda,  # API calls will trigger this Lambda
          proxy=True  # Proxy integration sends all requests to the Lambda
      )