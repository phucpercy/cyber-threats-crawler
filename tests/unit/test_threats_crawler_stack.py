import aws_cdk as core
import aws_cdk.assertions as assertions

from threats_crawler.threats_crawler_stack import ThreatsCrawlerStack

# example tests. To run these tests, uncomment this file along with the example
# resource in threats_crawler/threats_crawler_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = ThreatsCrawlerStack(app, "threats-crawler")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
