import aws_cdk as cdk
from constructs import Construct

from threats_crawler.threats_crawler_stack import ThreatsCrawlerStack


class PipelineAppStage(cdk.Stage):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        ThreatsCrawlerStack(self, "ThreatCrawlerStack", construct_id)